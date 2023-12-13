import random
import math

def generate_rsa_keypair(bits=1024):
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(2, phi)
    while math.gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = mod_inverse(e, phi)

    return ((e, n), (d, n))

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_prime(bits):
    candidate = random.getrandbits(bits)
    while not is_prime(candidate):
        candidate = random.getrandbits(bits)
    return candidate

def is_prime(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, n - 1, n)
        if x != 1:
            return False

    return True

def encrypt(key, public_key):
    e, n = public_key
    encrypted_key = pow(key, e, n)
    return encrypted_key

def decrypt(encrypted_key, private_key):
    d, n = private_key
    decrypted_key = pow(encrypted_key, d, n)
    return decrypted_key
