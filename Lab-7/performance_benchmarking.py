from time import perf_counter
from Crypto.Util.number import inverse, getPrime
from math import gcd, lcm
from secrets import randbelow

def generate_paillier_keypair(bits=512):
    # Generate the two secret primes.
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)

    n = p * q
    n_squared = n * n
    g = n + 1

    # Private-key values used by Paillier decryption.
    lam = lcm(p - 1, q - 1)

    # For g = n + 1, L(g^lambda mod n^2) equals lambda mod n.
    mu = inverse(lam, n)

    public_key = (n, g)
    private_key = (lam, mu)

    return public_key, private_key


def paillier_encrypt(public_key, message):
    n, g = public_key
    n_squared = n * n

    if not 0 <= message < n:
        raise ValueError("Message must be between 0 and n - 1.")

    # Choose fresh randomness r such that gcd(r, n) = 1.
    while True:
        r = randbelow(n)
        if r > 0 and gcd(r, n) == 1:
            break

    return (pow(g, message, n_squared) *
            pow(r, n, n_squared)) % n_squared


def paillier_decrypt(public_key, private_key, ciphertext):
    n, _ = public_key
    lam, mu = private_key
    n_squared = n * n

    u = pow(ciphertext, lam, n_squared)
    L_u = (u - 1) // n

    return (L_u * mu) % n

public_key,_=generate_paillier_keypair(1024)
start = perf_counter()
ciphertext = paillier_encrypt(public_key, 15)
elapsed = perf_counter() - start

print(f"Paillier encryption time: {elapsed:.6f} seconds")