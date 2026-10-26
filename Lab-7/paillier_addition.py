from math import gcd, lcm
from secrets import randbelow
from Crypto.Util.number import getPrime, inverse


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


def paillier_add(public_key, ciphertext_a, ciphertext_b):
    n, _ = public_key
    return (ciphertext_a * ciphertext_b) % (n * n)


# Demonstration
public_key, private_key = generate_paillier_keypair()

a = 15
b = 25

encrypted_a = paillier_encrypt(public_key, a)
encrypted_b = paillier_encrypt(public_key, b)

encrypted_sum = paillier_add(public_key, encrypted_a, encrypted_b)
decrypted_sum = paillier_decrypt(public_key, private_key, encrypted_sum)

print("Ciphertext of 15:", encrypted_a)
print("Ciphertext of 25:", encrypted_b)
print("Encrypted sum:", encrypted_sum)
print("Decrypted sum:", decrypted_sum)
print("Correct:", decrypted_sum == a + b)