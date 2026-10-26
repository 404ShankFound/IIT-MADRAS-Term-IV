from secrets import randbelow
from Crypto.Util.number import getPrime, inverse


def elgamal_generate_keypair(bits=512):
    p = getPrime(bits)

    # Educational choice of generator; proper group parameters matter in real systems.
    g = 2
    x = randbelow(p - 2) + 1
    y = pow(g, x, p)

    public_key = (p, g, y)
    private_key = x
    return public_key, private_key


def elgamal_encrypt(public_key, message):
    p, g, y = public_key

    if not 1 <= message < p:
        raise ValueError("Message must be a nonzero value less than p.")

    r = randbelow(p - 2) + 1
    c1 = pow(g, r, p)
    c2 = (message * pow(y, r, p)) % p

    return (c1, c2)


def elgamal_decrypt(public_key, private_key, ciphertext):
    p, _, _ = public_key
    c1, c2 = ciphertext

    shared = pow(c1, private_key, p)
    return (c2 * inverse(shared, p)) % p


def elgamal_multiply(ciphertext_a, ciphertext_b, public_key):
    p, _, _ = public_key
    a1, a2 = ciphertext_a
    b1, b2 = ciphertext_b

    return ((a1 * b1) % p, (a2 * b2) % p)


public_key, private_key = elgamal_generate_keypair()

a = 7
b = 3

encrypted_a = elgamal_encrypt(public_key, a)
encrypted_b = elgamal_encrypt(public_key, b)

encrypted_product = elgamal_multiply(
    encrypted_a, encrypted_b, public_key
)
decrypted_product = elgamal_decrypt(
    public_key, private_key, encrypted_product
)

print("Encrypted product:", encrypted_product)
print("Decrypted product:", decrypted_product)
print("Correct:", decrypted_product == (a * b) % public_key[0])