from math import gcd
from Crypto.Util.number import getPrime, inverse


def generate_rsa_keypair(bits=512):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)

    N = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        raise RuntimeError("Could not use this prime pair; generate another pair.")

    d = inverse(e, phi)

    public_key = (N, e)
    private_key = (N, d)

    return public_key, private_key


def rsa_encrypt(public_key, message):
    N, e = public_key
    if not 0 <= message < N:
        raise ValueError("Message must be between 0 and N - 1.")
    return pow(message, e, N)


def rsa_decrypt(private_key, ciphertext):
    N, d = private_key
    return pow(ciphertext, d, N)


def rsa_homomorphic_multiply(public_key, ciphertext_a, ciphertext_b):
    N, _ = public_key
    return (ciphertext_a * ciphertext_b) % N


# Demonstration
public_key, private_key = generate_rsa_keypair()

a = 7
b = 3

encrypted_a = rsa_encrypt(public_key, a)
encrypted_b = rsa_encrypt(public_key, b)

encrypted_product = rsa_homomorphic_multiply(
    public_key, encrypted_a, encrypted_b
)
decrypted_product = rsa_decrypt(private_key, encrypted_product)

print("Ciphertext of 7:", encrypted_a)
print("Ciphertext of 3:", encrypted_b)
print("Encrypted product:", encrypted_product)
print("Decrypted product:", decrypted_product)
print("Correct:", decrypted_product == a * b)