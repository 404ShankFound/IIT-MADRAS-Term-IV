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


def paillier_add(public_key, ciphertext_a, ciphertext_b):
    n, _ = public_key
    return (ciphertext_a * ciphertext_b) % (n * n)

# Assume generate_paillier_keypair, paillier_encrypt,
# paillier_add, and paillier_decrypt are defined as above.

public_key, private_key = generate_paillier_keypair()

alice_ciphertext = paillier_encrypt(public_key, 40)
bob_ciphertext = paillier_encrypt(public_key, 60)

combined_ciphertext = paillier_add(
    public_key,
    alice_ciphertext,
    bob_ciphertext
)

print("Alice's ciphertext:", alice_ciphertext)
print("Bob's ciphertext:", bob_ciphertext)
print("Combined encrypted total:", combined_ciphertext)

# Only the party holding the private key can decrypt the final total.
total = paillier_decrypt(public_key, private_key, combined_ciphertext)
print("Decrypted total:", total)