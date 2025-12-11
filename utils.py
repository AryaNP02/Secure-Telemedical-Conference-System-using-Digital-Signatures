import random
import math
import sympy
import hashlib


def logger(msg):
    print("logger ", msg)


def find_generator(p):
    """Finds a primitive root (generator) for a given prime p."""
    factors = sympy.factorint(p - 1)  # Prime factorization of (p-1)
    for g in range(2, p):  # Try values from 2 to p-1
        if all(pow(g, (p-1)//q, p) != 1 for q in factors):
            return g
    return None 


def modinv(a, p):
    return pow(a, -1, p)


def hash_data(data):
    return hashlib.sha256(data).digest()


def int_to_bytes(n, length):
    return n.to_bytes(length, 'big')


def bytes_to_int(b):
    return int.from_bytes(b, 'big')
