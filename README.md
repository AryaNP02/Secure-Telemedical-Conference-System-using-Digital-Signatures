# Secure Telemedical Conference System using Digital Signatures

## Project Description
This project implements a secure telemedical conference system as part of Lab Assignment 2 for the System and Network Security (CS5.470) course at the International Institute of Information Technology Hyderabad. The system ensures secure authentication, encrypted communication, and message integrity between a doctor (Gateway Node, GWN) and multiple patients using cryptographic protocols.

It leverages the ElGamal cryptosystem for key exchange and digital signatures, AES-256 for message encryption, and a robust authentication mechanism to prevent unauthorized access and ensure patient confidentiality.

### Main Components:
- `doctor.py`: Implements the doctor's device (GWN) that manages patient connections, authenticates patients, and broadcasts messages.
- `patient.py`: Implements the patient's device (Di) that authenticates with the doctor and receives broadcast messages.
- `utils.py`: Provides utility functions for logging, hashing, and modular arithmetic.
- `elgamal.py`: Implements the ElGamal cryptosystem for key generation, encryption, decryption, signing, and verification.

## Problem Statement
The assignment requires designing a secure telemedical platform where a doctor can interact confidentially with multiple patients. The key objectives are:
- **Secure Authentication**: Both the doctor and patients must authenticate using cryptographic protocols before initiating a secure session.
- **Encrypted Communication**: Sensitive medical data must be protected using AES-256 encryption.
- **Message Integrity**: Cryptographic signatures (ElGamal) must ensure message integrity.
- **Key Exchange**: Session keys must be securely exchanged using the ElGamal cryptosystem.
- **Broadcasting**: The doctor must securely broadcast messages (e.g., unavailability schedule) to all authenticated patients using a shared group key.
- **Security Considerations**: The system must handle multiple patients concurrently, prevent replay attacks using timestamps, and block unauthorized access attempts for 24 hours.

## Technologies Used
### Programming Language
- Python 3.8+

### Libraries
- `cryptography`: For AES-256 encryption and decryption with CBC mode and PKCS7 padding.
- `sympy`: For generating large primes and performing prime factorization.
- `hashlib`: For SHA-256 hashing.
- `socket`: For network communication between the doctor and patients.
- `threading`: For handling multiple patient connections concurrently.
- `json`: For serializing messages between the doctor and patients.
- `os` and `random`: For generating random numbers and keys.

### Cryptographic Primitives
- **ElGamal cryptosystem**: For key exchange, encryption, and digital signatures.
- **AES-256**: For encrypting messages and group keys.
- **SHA-256**: For hashing session keys and verifiers.

## Installation Steps


### Install Dependencies
```bash
pip install cryptography sympy
```

### Verify Files
Ensure the following files are present in the project directory:
- `doctor.py`
- `patient.py`
- `utils.py`
- `elgamal.py`

## How It Works
The system operates in three main phases:

### Phase 1: Initialization
- Each participant (doctor and patients) generates an **ElGamal key pair**.
- A large prime `p` and generator `g` are selected.
- A private key `x` is chosen, and the public key `y = g^x mod p` is computed.

### Phase 2: Authentication and Key Exchange
- **Patient Authentication Request:** The patient generates a timestamp, a random nonce, and a session key, encrypts it using the doctor’s public key, signs the request, and sends it to the doctor.
- **Doctor Verification and Response:** The doctor verifies the request, decrypts the session key, and responds with a signed confirmation.
- **Patient Verification:** The patient verifies the doctor’s response and computes the shared session key.
- **Doctor Final Verification:** The doctor verifies the session key before granting access.

### Phase 3: Secure Message Broadcasting
- The doctor computes a **group key (GK)** for all active patients.
- GK is encrypted for each patient using their session key.
- The doctor broadcasts messages encrypted with GK, which patients decrypt using GK.

## Usage Instructions
### Start the Doctor Server
```bash
python doctor.py
```
The doctor server will start on `127.0.0.1:8000` and wait for patient connections.

### Start Patient Instances
```bash
python patient.py patient1
python patient.py patient2
```
Each patient will connect to the doctor, authenticate, and wait for messages.

### Interact with the Doctor
- Type `broadcast` to send a message to all active patients.
- Type `disconnect` to disconnect all patients and end the session.

### Observe Patient Output
- Each patient terminal will display logs of authentication, group key reception, and decrypted broadcast messages.

### Stop the System
- Press `Ctrl+C` in each terminal or use the `disconnect` command on the doctor.

## Performance Analysis
The table below shows execution times for key cryptographic operations (measured in milliseconds):

| Cryptographic Operation | Execution Time (ms) |
|-------------------------|---------------------|
| Key Generation (ElGamal) | 0.00034 |
| AES Encryption | 0.03092 |
| Hash Computation | 0.00171 |
| Sign Generation (ElGamal) | 0.05567 |

## Security Considerations
- **Prime Size**: The current implementation uses 128-bit primes for ElGamal, which should be increased to at least 2048-bit in real-world applications.
- **Random Number Generation**: The system uses `random.randint`, which should be replaced with `secrets` for cryptographic security.
- **Timestamp Format**: Using ISO 8601 for timestamps would improve interoperability.
- **Signature Data Serialization**: JSON serialization should be used instead of comma-separated strings to avoid parsing errors.
- **Thread Safety**: Adding thread synchronization (e.g., `threading.Lock`) would improve reliability.



---
This project provides a **secure telemedical communication system** ensuring **confidentiality, integrity, and authentication** using strong cryptographic methods. Future improvements can enhance security, scalability, and usability for real-world deployments.

