import json
import time
import os
import random
import socket
import threading
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from utils import logger, modinv, hash_data, int_to_bytes, bytes_to_int
from elgamal import ElGamal
from cryptography.hazmat.backends import default_backend
import hashlib

class Doctor:
    def __init__(self, id, host='127.0.0.1', port=8000):
        self.id = id
        self.crypto = ElGamal()
        self.pub_key = self.crypto.public_key()
        # print(f"{self.id} started with pub key: {self.pub_key}")
        self.patient_keys = {}
        self.active_patients = set()
        self.patient_pubs = {}
        self.patient_socks = {}
        self.blocked_patients = {}
        self.group_key = None
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"Doctor server running on {self.host}:{self.port}, awaiting for patients...")

    def make_group_key(self):
        keys = [data["key"] for data in self.patient_keys.values()]
        seed = os.urandom(16)
        all_keys = b"".join(keys) + seed
        return hashlib.sha256(all_keys).digest()

    def swap_keys(self, sock):
        data = sock.recv(4096).decode()
        if not data:
            return
        msg = json.loads(data)
        if msg.get("opcode") == 5:
            pid = msg["patient_id"]
            patient_pub = tuple(msg["patient_public_key"])
            self.patient_pubs[pid] = patient_pub
            # print(f"Got patient {pid} pub key")
            self.crypto.p = patient_pub[0]
            self.crypto.g = patient_pub[1]
            self.crypto.y = pow(self.crypto.g, self.crypto.x, self.crypto.p)
            self.pub_key = (self.crypto.p, self.crypto.g, self.crypto.y)
            # print(f"Set doctor pub key: {self.crypto.public_key()}")
        reply = {"opcode": 6, "doctor_public_key": list(self.pub_key)}
        sock.send(json.dumps(reply).encode())
        # print(f"Sent pub key to patient: {pid}"

    def handle(self, sock, addr):
        self.swap_keys(sock)
        pid = None
        try:
            while True:
                data = sock.recv(4096).decode()
                # print("Received:")
                # logger(data)
                if not data:
                    print(f"{addr} disconnected")
                    break
                msg = json.loads(data)
                code = msg.get("opcode")
                if code == 10:
                    pid = msg["patient_id"]
                    # print(f"Auth request from {pid} at {addr}")

                    reply={}
                    if self.check_auth(pid, msg, sock,reply):
                        self.patient_socks[pid] = sock
                        # print(f"{pid} auth OK, sock saved")
                        reply = {"opcode": 11, "doctor_public_key": list(self.pub_key)}
                        sock.send(json.dumps(reply).encode())
                    else:
                        print(f"\033[31m{pid} auth failed, closing\033[0m")
                        sock.send(json.dumps(reply).encode())
                        sock.close()
                        break
                elif code == 30:
                    # print(f"Got verifier from {pid}")
                    reply={}
                    if self.check_verifier(pid, msg, reply):
                        self.active_patients.add(pid)
                        # print(f"{pid} fully active, sending group key")
                        self.group_key = self.make_group_key()
                        for p in self.active_patients:
                            self.send_group(p)
                    else:

                        self.blocked_patients[pid] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + 24 * 3600))
                        print(f"{pid} verifier failed, closing")
                        
                        sock.send(json.dumps(reply).encode())
                        sock.close()
                        break
        except Exception as e:
            print(f"\033[31mError with {pid} at {addr}: {e}\033[0m")
        finally:
            if pid and pid in self.patient_socks:
                del self.patient_socks[pid]
                self.active_patients.discard(pid)
                if self.active_patients:
                    self.group_key = self.make_group_key()
                    for p in self.active_patients:
                        self.send_group(p)
                else:
                    self.group_key = None
                # print(f"Removed {pid} sock")
            sock.close()

    def check_auth(self, pid, req, sock,reply):
      
        t1 = req["ts_i"]
        r1 = req["rn_i"]
        gid = req["id_gwn"]
        enc_key = tuple(req["encrypted_session_key"])
        sig = tuple(req["signature"])
        pub = tuple(req["public_key"])
         
        if pid in self.blocked_patients:
            if self.blocked_patients[pid] > t1:
                print(f"\033[31m{pid} is currently blocked\033[0m")
                return False
            else:
                del self.blocked_patients[pid]
                # print(f"{pid} block expired, continuing")

        
        self.patient_pubs[pid] = pub

        now = time.time()
        req_time = time.mktime(time.strptime(t1, "%Y-%m-%d %H:%M:%S"))

        if abs(now - req_time) > 300:
            print(f"\033[31mBad timestamp for {pid} (diff: {abs(now - req_time)})\033[0m")
            reply.update({"opcode": 70, "message": "timestamp mismatch"})
            return False
        

        print(f"\033[32mTimestamp OK for {pid}\033[0m")


        sign_data = f"{t1},{r1},{gid},{enc_key[0]},{enc_key[1]}"
        m = int.from_bytes(hash_data(sign_data.encode()), 'big') % self.crypto.p
       

        # logger(m)
        # logger(sig)

        if not self.crypto.verify(m, *sig, self.patient_pubs[pid][2]):
            print(f"\033[31mSignature bad for {pid}\033[0m")
            reply.update({"opcode": 70, "message": "signature verification failed"})
            return False
        
        print(f"\033[32mSignature OK for {pid}\033[0m")

        key = self.crypto.decrypt(enc_key)
        key_bytes = int_to_bytes(key, 16)

        if len(key_bytes) != 16:
            print(f"Wrong key length for {pid}: {len(key_bytes)}")
            reply.update({"opcode": 70, "message": "wrong key length"})
            return False
        
        # print(f"Got key for {pid}: {key_bytes}")
        # print(f"Saved key data for {pid}")

        t2 = time.strftime("%Y-%m-%d %H:%M:%S")
        r2 = random.randint(1, 1000000)
        enc_key2 = self.crypto.encrypt(bytes_to_int(key_bytes), pub[2])
        sign_data2 = f"{t2},{r2},{pid},{enc_key2[0]},{enc_key2[1]}"
        m2 = int.from_bytes(hash_data(sign_data2.encode()), 'big') % self.crypto.p
        sig2 = self.crypto.sign(m2)
        reply = {
            "opcode": 20,
            "ts_gwn": t2,
            "rn_gwn": r2,
            "id_d_i": pid,
            "encrypted_session_key": list(enc_key2),
            "signature": list(sig2)
        }
        # print("Sending")
        # logger(reply)
        sock.send(json.dumps(reply).encode())
        # print(f"Sent reply to {pid}")
        self.patient_keys[pid] = {
            "key": key_bytes,
            "ts_i": t1,
            "rn_i": r1,
            "ts_gwn": t2,
            "rn_gwn": r2,
            "sk": None
        }
        return True

    def check_verifier(self, pid, ver , reply):
        t3 = ver["ts_i_prime"]
        skv = ver["skv"]
        now = time.time()
        ver_time = time.mktime(time.strptime(t3, "%Y-%m-%d %H:%M:%S"))

        if abs(now - ver_time) > 300:
            print(f"\033[31mBad verifier time for {pid} (diff: {abs(now - ver_time)})\033[0m")
            reply.update({"opcode": 70, "message": " Verification failed due to Timestamp mismatch"})
            return False
        
        # print(f"Verifier time OK for {pid}")
        data = self.patient_keys[pid]
        key = data["key"]
        t1 = data["ts_i"]
        r1 = data["rn_i"]
        t2 = data["ts_gwn"]
        r2 = data["rn_gwn"]

        all_data = key + t1.encode() + t2.encode() + str(r1).encode() + str(r2).encode() + pid.encode() + self.id.encode()
        sk = hash_data(all_data)
        skv2 = hash_data(sk + t3.encode()).hex()

        if skv2 != skv:
            print(f"Verifier mismatch for {pid}: got {skv}, expected {skv2}")
        
            reply.update({"opcode": 70, "message": "session verification mismatch"})
            return False
        
        print(f"\033[32m20 : 'SESSION_TOKEN' :: Verifier OK for {pid}\033[0m")
        self.patient_keys[pid]["sk"] = sk
        return True

    def send_group(self, pid):

        if pid not in self.active_patients:
            return
        # logger(self.group_key)
        sk = self.patient_keys[pid]["sk"]
        iv = os.urandom(16)
        pad = padding.PKCS7(128).padder()
        cipher = Cipher(algorithms.AES(sk), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        padded = pad.update(self.group_key) + pad.finalize()
        enc_data = enc.update(padded) + enc.finalize()
        msg = {
            "opcode": 30,
            "iv": iv.hex(),
            "ciphertext": enc_data.hex()
        }
        self.patient_socks[pid].send(json.dumps(msg).encode())
        print(f"\033[32m30 : 'GROUP_KEY' :: Sent group key to {pid}\033[0m")

    def send_all(self, text):

        if not self.group_key:
            print("No group key, can’t send")
            return
        iv = os.urandom(16)
        pad = padding.PKCS7(128).padder()
        cipher = Cipher(algorithms.AES(self.group_key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        padded = pad.update(text.encode()) + pad.finalize()
        enc_data = enc.update(padded) + enc.finalize()
        msg = {
            "opcode": 40,
            "iv": iv.hex(),
            "ciphertext": enc_data.hex()
        }
        data = json.dumps(msg).encode()
        for pid, sock in list(self.patient_socks.items()):
            try:
                sock.send(data)
                print(f"Sent to {pid}: {text}")
            except:
                print(f"Failed to send to {pid}, dropping")
                del self.patient_socks[pid]

    def start(self):
        bg = threading.Thread(target=self.run_input)
        bg.daemon = True
        bg.start()
        # print("Started broadcasting thread")
        while True:
            sock, addr = self.server.accept()
            print(f"New patient at {addr}")
            t = threading.Thread(target=self.handle, args=(sock, addr))
            t.start()
            # print(f"Handling {addr}")

    def run_input(self):
        while True:
            cmd = input()
            if cmd == "broadcast":

                text = input("\033[33mMessage: \033[0m")
                # logger(self.group_key)
                iv = os.urandom(16)
                pad = padding.PKCS7(128).padder()
                cipher = Cipher(algorithms.AES(self.group_key), modes.CBC(iv), backend=default_backend())
                enc = cipher.encryptor()
                padded = pad.update(text.encode()) + pad.finalize()
                enc_data = enc.update(padded) + enc.finalize()
                pkt = {
                    "opcode": 40,
                    "iv": iv.hex(),
                    "ciphertext": enc_data.hex()
                }
                for pid, sock in self.patient_socks.items():
                    try:
                        sock.send(json.dumps(pkt).encode())
                    except:
                        pass
                print(f"\033[32m40 : 'ENC_MSG' :: Encrypted msg sent.\033[0m")

            elif cmd == "disconnect":
                if self.patient_socks:
                    for pid, sock in list(self.patient_socks.items()):
                        try:
                            if pid in self.patient_keys and self.patient_keys[pid].get("sk"):
                                sk = self.patient_keys[pid]["sk"]
                                text = "disconnect"
                                iv = os.urandom(16)
                                pad = padding.PKCS7(128).padder()
                                enc = Cipher(algorithms.AES(sk), modes.CBC(iv), backend=default_backend()).encryptor()
                                padded = pad.update(text.encode()) + pad.finalize()
                                enc_data = enc.update(padded) + enc.finalize()
                                pkt = {
                                    "opcode": 60,
                                    "iv": iv.hex(),
                                    "ciphertext": enc_data.hex()
                                }
                                sock.send(json.dumps(pkt).encode())
                            sock.close()
                            del self.patient_socks[pid]
                            self.active_patients.discard(pid)
                        except:
                            pass
                    self.group_key = None
                    print(f"\033[31m60 : 'DISCONNECT' :: Disconnected from patients\033[0m")
                    self.patient_socks.clear()
                else:
                    print("\033[31mNo patients connected\033[0m")
            
            elif cmd == "":
                continue

if __name__ == "__main__":
    doc = Doctor("doctor1")
    doc.start()