import json
import time
import os
import random
import socket
from cryptography.hazmat.primitives import padding
from utils import logger, modinv, hash_data, int_to_bytes, bytes_to_int
from elgamal import ElGamal
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib

class Patient:
    def __init__(self, pid, did, host='127.0.0.1', port=8000):
        self.pid = pid
        self.doc_pub = -1
        self.did = did
        self.crypto = ElGamal()
        # print(f"Patient {self.pid} started with pub key: {self.crypto.public_key()}")
        self.key = os.urandom(16)
        self.group_key = None
        self.sk = None
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"Patient {self.pid} connecting to {self.host}:{self.port}")
        self.sock.connect((self.host, self.port))
        print(f"Patient {self.pid} connected")
        self.t1 = None
        self.r1 = None

    def send_auth(self):
        self.t1 = time.strftime("%Y-%m-%d %H:%M:%S")
        self.r1 = random.randint(1, 1000000)
        # logger(self.doc_pub)
        enc_key = self.crypto.encrypt(bytes_to_int(self.key), self.doc_pub[2])
        sign_data = f"{self.t1},{self.r1},{self.did},{enc_key[0]},{enc_key[1]}"
        m = int.from_bytes(hash_data(sign_data.encode()), 'big') % self.crypto.p
        # print(m)
        sig = self.crypto.sign(m)
        req = {
            "opcode": 10,
            "patient_id": self.pid,
            "ts_i": self.t1,
            "rn_i": self.r1,
            "id_gwn": self.did,
            "encrypted_session_key": list(enc_key),
            "signature": list(sig),
            "public_key": list(self.crypto.public_key())
        }
        # print(req)
        self.sock.send(json.dumps(req).encode())
        # print(f"Patient {self.pid} sent auth request")

    def check_doc_reply(self, reply):

        # print("Doc reply", reply)

        t2 = reply["ts_gwn"]
        r2 = reply["rn_gwn"]
        my_id = reply["id_d_i"]
        enc_key = tuple(reply["encrypted_session_key"])
        sig = tuple(reply["signature"])

        # print(sig)

        # print(f"Patient {self.pid} got doc reply")

        now = time.time()
        reply_time = time.mktime(time.strptime(t2, "%Y-%m-%d %H:%M:%S"))

        if abs(now - reply_time) > 300:
            print(f"Bad timestamp (diff: {abs(now - reply_time)})")
            return False
        
        # print(f"Timestamp OK")
        sign_data = f"{t2},{r2},{my_id},{enc_key[0]},{enc_key[1]}"
        m = int.from_bytes(hash_data(sign_data.encode()), 'big') % self.crypto.p
        # print("Doc pub key:", self.doc_pub[2])

        if not self.crypto.verify(m, *sig, self.doc_pub[2]):
            print(f"Signature failed")
            return False
        
        # print(f"Signature OK")

        got_key = self.crypto.decrypt(enc_key)
        got_bytes = int_to_bytes(got_key, 16)

        if got_bytes != self.key:
            print(f"Key mismatch: got {got_bytes.hex()}, expected {self.key.hex()}")
            return False
        
        print(f"\033[32m10: 'KEY_VERIFICATION' :: Key OK for {self.pid}\033[0m")
        all_data = self.key + self.t1.encode() + t2.encode() + str(self.r1).encode() + str(r2).encode() + self.pid.encode() + self.did.encode()
        self.sk = hash_data(all_data)
        # print(f"Set sk for {self.pid}")
        return True

    def send_verifier(self):
        t3 = time.strftime("%Y-%m-%d %H:%M:%S")
        skv = hash_data(self.sk + t3.encode()).hex()
        ver = {
            "opcode": 30,
            "ts_i_prime": t3,
            "skv": skv
        }
        self.sock.send(json.dumps(ver).encode())
        print(f"\033[32m20: 'SESSION_TOKEN' :: Patient {self.pid} sent verifier\033[0m")

    def get_group(self, msg):

        iv = bytes.fromhex(msg["iv"])
        enc = bytes.fromhex(msg["ciphertext"])
        cipher = Cipher(algorithms.AES(self.sk), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        padded = dec.update(enc) + dec.finalize()
        unp = padding.PKCS7(128).unpadder()
        self.group_key = unp.update(padded) + unp.finalize()
        print(f"\033[32m30: 'GROUP_KEY' :: Patient {self.pid} got group key\033[0m")

    def swap_keys(self):

        msg = {
            "opcode": 5,
            "patient_id": self.pid,
            "patient_public_key": list(self.crypto.public_key())
        }

        self.sock.send(json.dumps(msg).encode())
        data = self.sock.recv(4096).decode()
        reply = json.loads(data)

        if reply.get("opcode") == 6:
            self.doc_pub = tuple(reply["doctor_public_key"])
            # print(f"Got doc pub key: {self.doc_pub}")

    def start(self):

        self.swap_keys()
        self.send_auth()

        while True:
            try:
                data = self.sock.recv(4096).decode()
                if not data:
                    print(f"Patient {self.pid} lost connection")
                    break
                msg = json.loads(data)
                code = msg["opcode"]
                if code == 20:

                    # print(f"Patient {self.pid} checking doc reply")

                    if self.check_doc_reply(msg):
                        self.send_verifier()
                elif code == 30:
                    # print(f"Patient {self.pid} got group key msg")
                    self.get_group(msg)
                elif code == 40:
                    # logger("lllll")
                    # logger(len(self.group_key))
                    # logger(self.group_key)
                    # logger("lllll")
                    print(f"\033[32m{code}: Patient {self.pid} got broadcast\033[0m")
                    iv = bytes.fromhex(msg["iv"])
                    enc = bytes.fromhex(msg["ciphertext"])
                    cipher = Cipher(algorithms.AES(self.group_key), modes.CBC(iv), backend=default_backend())
                    dec = cipher.decryptor()
                    padded = dec.update(enc) + dec.finalize()
                    unp = padding.PKCS7(128).unpadder()
                    text = unp.update(padded) + unp.finalize()
                    print(f"\033[32m50 : 'DEC_MSG' :: Patient {self.pid} decrypted: \033[0m\033[33m{text.decode()}\033[0m")
                elif code == 60:
                    iv = bytes.fromhex(msg["iv"])
                    enc = bytes.fromhex(msg["ciphertext"])
                    dec = Cipher(algorithms.AES(self.sk), modes.CBC(iv), backend=default_backend()).decryptor()
                    unp = padding.PKCS7(128).unpadder()
                    padded = dec.update(enc) + dec.finalize()
                    text = unp.update(padded) + unp.finalize()
                    print(f"\033[31m{code}: Patient {self.pid} got: {text.decode()}\033[0m")
                    self.sock.close()
                    break
                elif code == 70:
                    print(f"\033[31mError: Patient {self.pid}  get  {msg['message']}\033[0m")
                    self.sock.close()
                    break
            except Exception as e:
                print(f"Error in {self.pid}: {e}")
                break

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python patient.py <patient_id>")
        sys.exit(1)
    pid = sys.argv[1]
    patient = Patient(pid, "doctor1")
    patient.start()