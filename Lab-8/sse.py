
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# 1. Secret keys
aes_key = get_random_bytes(16)
search_key = get_random_bytes(32)

# 2. Ten-document corpus
documents = {
    "doc1": "AES secures digital messages",
    "doc2": "RSA uses public and private keys",
    "doc3": "AES encryption protects sensitive data",
    "doc4": "Network security detects attacks",
    "doc5": "Digital signatures verify identity",
    "doc6": "Python supports cryptographic libraries",
    "doc7": "Secure networks require strong encryption",
    "doc8": "RSA supports digital signatures",
    "doc9": "AES uses symmetric encryption",
    "doc10": "Network monitoring detects suspicious traffic"
}

# 3. AES-CBC encryption
def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(
        pad(data, AES.block_size)
    )
    return iv, ciphertext

# 4. AES-CBC decryption
def decrypt_data(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    )
    return plaintext

# 5. Deterministic, keyed search token
def make_token(word):
    word = word.lower().strip()
    return hmac.new(
        search_key,
        word.encode(),
        hashlib.sha256
    ).digest()

# 6. Encrypt all documents
encrypted_documents = {}

for doc_id, text in documents.items():
    encrypted_documents[doc_id] = encrypt_data(
        aes_key, text.encode()
    )

# 7. Create the encrypted inverted index
encrypted_index = {}

for doc_id, text in documents.items():
    words = set(text.lower().split())

    for word in words:
        token = make_token(word)

        if token not in encrypted_index:
            encrypted_index[token] = []

        # Each ID is encrypted with a fresh IV
        encrypted_id = encrypt_data(
            aes_key, doc_id.encode()
        )
        encrypted_index[token].append(encrypted_id)

# 8. Search the index
def search(query):
    token = make_token(query)
    matches = encrypted_index.get(token, [])

    result_ids = []

    for iv, ciphertext in matches:
        doc_id = decrypt_data(
            aes_key, iv, ciphertext
        ).decode()

        result_ids.append(doc_id)

    return result_ids

# 9. Search and decrypt matching documents
query = input("Enter a word to search: ").lower().strip()
results = search(query)

if results:
    print("\nMatching documents:")
    for doc_id in results:
        iv, ciphertext = encrypted_documents[doc_id]
        plaintext = decrypt_data(
            aes_key, iv, ciphertext
        ).decode()

        print(doc_id, ":", plaintext)
else:
    print("No matching documents found.")
