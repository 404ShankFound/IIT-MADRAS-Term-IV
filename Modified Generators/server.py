# Install dependency:
# python -m pip install pycryptodome
#
# TCP server; serial request dispatch with authenticated permissions.
# Timestamp trust and two-authority separation are simulated locally.
# A real deployment needs separate authority machines and a trusted time service.

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ElGamal
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime

from pathlib import Path
from datetime import datetime, timedelta, timezone
from time import perf_counter
from getpass import getpass
from math import gcd, lcm

import hashlib
import hmac
import json
import secrets
import os
import re


BASE = Path(__file__).resolve().parent / "server_data"
IST = timezone(timedelta(hours=5, minutes=30))
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"



ROLE = None
EVENTS = []

FOLDERS = [
    "keys",
    "authorities",
    "encrypted",
    "encrypted_key",
    "iv",
    "hashes",
    "signature",
    "public_key",
    "paillier",
    "metadata",
    "index",
    "receipts",
    "verified",
    "tally",
]


# =========================================================
# FILE STORAGE, TIMESTAMPS AND TIMINGS
# =========================================================


ALGORITHMS = {'encryption': 'AES-256', 'hash': 'SHA-512', 'key': 'RSA', 'signature': 'ElGamal', 'search': 'SSE', 'rsa_bits': {'key': 4096, 'signature': 2048, 'search': 2048}, 'cipher': {'mode': 'CBC', 'padding': 'PKCS7', 'iv_source': 'random', 'iv_hex': ''}, 'show_paillier_on_submit': True}

DOMAIN = {'title': 'Secure Electronic Voting', 'record_name': 'Ballot', 'fields': [{'name': 'CandidateID', 'type': 'choice', 'search': False, 'sum': False, 'count': True, 'choices': ['1', '2', '3']}, {'name': 'ConstituencyID', 'type': 'text', 'search': True, 'sum': False, 'count': False}], 'use_deadline': True, 'close_on_aggregate': True, 'min_records': 2}
ENTITIES = {'Voter': ['submit_record', 'view_own_records', 'view_own_signatures'], 'Election Server': ['verify_record', 'search_records', 'view_all_records', 'view_signature', 'view_metadata'], 'Tally Authority': ['aggregate_records', 'threshold_decrypt', 'select_records', 'view_aggregate_ciphertext']}
DOMAIN_ACTIONS = {'submit_record': 'Submit record: hash, sign, encrypt, protect key, encrypt totals and index', 'verify_record': 'Verify record: decrypt internally, compare hashes/signature and validate metadata', 'view_record': 'View full record details (all submissions; plaintext fields)', 'search_records': 'Search text by words, other fields by exact value, or submission time', 'aggregate_records': 'Aggregate selected verified records (Paillier addition)', 'threshold_decrypt': 'Decrypt aggregate using both authority passwords', 'view_all_records': 'List all submitted records (permitted fields)', 'view_own_records': 'View all submitted by me (including contents)', 'view_own_signatures': 'View all digital signatures by me', 'view_text': 'View plaintext text/description and category fields', 'view_amounts': 'View individual numeric/amount fields', 'view_ciphertext': 'View ciphertext (key shown only to its submitter)', 'view_signature': 'View an existing digital signature', 'select_records': 'Select record IDs for aggregation', 'verify_selected': 'Verify selected records', 'rsa_multiply': 'RSA homomorphic multiplication (no OAEP padding)', 'elgamal_multiply': 'ElGamal homomorphic multiplication', 'compare_demo': 'Compare numbers after ElGamal decryption', 'view_aggregate_ciphertext': 'View saved Paillier aggregate ciphertext (no decryption)', 'view_metadata': 'View record metadata only (no plaintext fields)'}
METRICS = {'record_count': {'kind': 'record_count', 'label': 'Record count', 'scale': 1, 'decimals': 0}, 'count_0_0': {'kind': 'count', 'label': 'CandidateID = 1', 'field': 'CandidateID', 'choice': '1', 'scale': 1, 'decimals': 0}, 'count_0_1': {'kind': 'count', 'label': 'CandidateID = 2', 'field': 'CandidateID', 'choice': '2', 'scale': 1, 'decimals': 0}, 'count_0_2': {'kind': 'count', 'label': 'CandidateID = 3', 'field': 'CandidateID', 'choice': '3', 'scale': 1, 'decimals': 0}, 'choice_sum_CandidateID': {'kind': 'sum', 'label': 'Total CandidateID', 'field': 'CandidateID', 'scale': 1, 'decimals': 0}}

def now():
    return datetime.now(IST).strftime(TIME_FORMAT)

def save(folder, filename, value):
    path = BASE / folder / filename
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")

def read(folder, filename):
    path = BASE / folder / filename
    return json.loads(path.read_text(encoding="utf-8"))

def timed(operation, function, *args):
    started_at = datetime.now(IST).isoformat(timespec="milliseconds")
    start = perf_counter()
    status = "success"

    try:
        result = function(*args)

        if result is False:
            status = "failed"

        return result

    except Exception:
        status = "error"
        raise

    finally:
        EVENTS.append({
            "operation": operation,
            "started_at": started_at,
            "finished_at": datetime.now(IST).isoformat(
                timespec="milliseconds"
            ),
            "duration_ms": (perf_counter() - start) * 1000,
            "status": status,
        })

def show_summary(action, details):
    timestamp = datetime.now(IST).isoformat(timespec="milliseconds")

    print(f"\n[{timestamp}] {ROLE.upper()} - {action}")

    for name, value in details.items():
        print(name + ":", value)

    totals = {}

    for event in EVENTS:
        name = event["operation"]
        totals[name] = totals.get(name, 0) + event["duration_ms"]

    if totals:
        print(
            "Times (ms):",
            " | ".join(
                f"{name}={duration:.6f}"
                for name, duration in totals.items()
            ),
        )

    entry = {
        "timestamp": timestamp,
        "role": ROLE,
        "action": action,
        "details": "Output omitted from shared audit log",
        "events": list(EVENTS),
    }

    with (BASE / "events.jsonl").open("a", encoding="utf-8") as file:
        file.write(json.dumps(entry) + "\n")

def password_key(password, salt):
    return hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=32,
    )

def new_password(label):
    while True:
        password = getpass(f"Set {label} password: ")
        confirmation = getpass("Confirm password: ")

        if password and password == confirmation:
            return password

        print("Passwords must be nonempty and match.")

def login(role):
    account = read("keys", "accounts.json")[role]
    password = getpass(f"{role.capitalize()} password: ")

    actual = password_key(
        password,
        bytes.fromhex(account["salt"]),
    ).hex()

    if not hmac.compare_digest(actual, account["hash"]):
        print("Access denied.")
        return False

    return True

def protect_share(number, share, password):
    salt = os.urandom(16)
    key = password_key(password, salt)

    cipher = AES.new(key, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(
        str(share).encode()
    )

    save("authorities", f"{number}.json", {
        "salt": salt.hex(),
        "nonce": cipher.nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
    })

def unlock_share(number, password):
    record = read("authorities", f"{number}.json")

    key = password_key(
        password,
        bytes.fromhex(record["salt"]),
    )

    cipher = AES.new(
        key,
        AES.MODE_EAX,
        nonce=bytes.fromhex(record["nonce"]),
    )

    plaintext = cipher.decrypt_and_verify(
        bytes.fromhex(record["ciphertext"]),
        bytes.fromhex(record["tag"]),
    )

    return int(plaintext.decode())

def setup():
    for folder in FOLDERS:
        (BASE / folder).mkdir(parents=True, exist_ok=True)

    if (BASE / "keys" / "settings.json").exists():
        return

    if any((BASE / "keys").iterdir()):
        raise ValueError(
            "Incomplete setup. Use a fresh record_files folder."
        )

    print("\nFIRST-RUN SYSTEM SETUP")
    print("Enter dates in IST using YYYY-MM-DD HH:MM:SS.")

    start = datetime.strptime(
        input("Submissions start: ").strip(),
        TIME_FORMAT,
    )

    deadline = datetime.strptime(
        input("Submission deadline: ").strip(),
        TIME_FORMAT,
    )

    if deadline <= start:
        raise ValueError("Deadline must be after the starting time.")

    accounts = {}

    for role in ENTITIES:
        password = new_password(role)
        salt = os.urandom(16)

        accounts[role] = {
            "salt": salt.hex(),
            "hash": password_key(password, salt).hex(),
        }

    authority_passwords = [
        new_password("authority 1"),
        new_password("authority 2"),
    ]

    if ALGORITHMS["key"] == "RSA":
        print("Generating RSA-" + str(ALGORITHMS["rsa_bits"]["key"]) + " keys...")

        rsa_key = RSA.generate(ALGORITHMS["rsa_bits"]["key"])

        save(
            "keys",
            "rsa_private.json",
            rsa_key.export_key().decode(),
        )

        save(
            "keys",
            "rsa_public.json",
            rsa_key.publickey().export_key().decode(),
        )

    print("Generating Paillier parameters...")

    while True:
        p = getPrime(1024)
        q = getPrime(1024)

        n = p * q
        lam = lcm(p - 1, q - 1)

        if p != q and gcd(lam, n) == 1:
            break

    # d is divisible by lambda, and d mod n = 1.
    # Therefore L(c^d mod n²) recovers the plaintext modulo n.
    d = lam * pow(lam, -1, n)
    period = n * lam

    share1 = secrets.randbelow(period - 1) + 1
    share2 = (d - share1) % period

    protect_share(1, share1, authority_passwords[0])
    protect_share(2, share2, authority_passwords[1])

    save("keys", "paillier_public.json", {
        "n": n,
        "g": n + 1,
    })

    # Do not persist p, q, lambda or the complete exponent d.
    del p, q, lam, d, period, share1, share2

    print("Generating ElGamal parameters...")

    elgamal = ElGamal.generate(512, os.urandom)

    save("keys", "elgamal.json", {
        "p": int(elgamal.p),
        "g": int(elgamal.g),
    })

    save("keys", "accounts.json", accounts)
    save("keys", "search_key.json", os.urandom(32).hex())
    save("keys", "receipt_key.json", os.urandom(32).hex())

    save("keys", "settings.json", {
        "start": start.strftime(TIME_FORMAT),
        "deadline": deadline.strftime(TIME_FORMAT),
        "created_at": now(),
    })

    print("Setup complete.")

def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)

    ciphertext = cipher.encrypt(
        pad(plaintext.encode(), AES.block_size)
    )

    return cipher.iv.hex(), ciphertext.hex()

def aes_decrypt(ciphertext, key, iv):
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=bytes.fromhex(iv),
    )

    plaintext = unpad(
        cipher.decrypt(bytes.fromhex(ciphertext)),
        AES.block_size,
    )

    return plaintext.decode()

def rsa_encrypt_key(key):
    public_key = RSA.import_key(
        read("keys", "rsa_public.json")
    )

    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)

    return cipher.encrypt(key).hex()

def rsa_decrypt_key(ciphertext):
    private_key = RSA.import_key(
        read("keys", "rsa_private.json")
    )

    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)

    return cipher.decrypt(bytes.fromhex(ciphertext))

def hash_message(message):
    return hashlib.sha512(message.encode()).hexdigest()

def generate_signing_keys():
    parameters = read("keys", "elgamal.json")

    p = parameters["p"]
    g = parameters["g"]

    private_key = secrets.randbelow(p - 2) + 1

    public_key = {
        "p": p,
        "g": g,
        "y": pow(g, private_key, p),
    }

    return private_key, public_key

def sign_hash(digest, private_key, public_key, trace=None):
    p = public_key["p"]
    g = public_key["g"]

    while True:
        k = secrets.randbelow(p - 2) + 1

        if gcd(k, p - 1) == 1:
            break

    if trace is not None:
        trace["ElGamal signing nonce k"] = k
    r = pow(g, k, p)

    s = (
        (int(digest, 16) - private_key * r)
        * pow(k, -1, p - 1)
    ) % (p - 1)

    return [r, s]

def signature_values(digest, signature, public_key):
    p = public_key["p"]
    g = public_key["g"]
    y = public_key["y"]

    r, s = signature

    if not (0 < r < p and 0 <= s < p - 1):
        raise ValueError("Invalid ElGamal signature values.")

    expected = pow(g, int(digest, 16), p)

    actual = (
        pow(y, r, p) * pow(r, s, p)
    ) % p

    return expected, actual

def verify_signature(digest, signature, public_key):
    expected, actual = signature_values(
        digest, signature, public_key
    )

    return expected == actual

def paillier_encrypt(message, n):
    if not 0 <= message < n:
        raise ValueError("Message outside Paillier range.")

    while True:
        r = secrets.randbelow(n - 1) + 1

        if gcd(r, n) == 1:
            break

    ciphertext = (
        pow(n + 1, message, n * n)
        * pow(r, n, n * n)
    ) % (n * n)

    return ciphertext, r

def search_token(value):
    key = bytes.fromhex(read("keys", "search_key.json"))

    return hmac.new(
        key,
        value.encode(),
        hashlib.sha256,
    ).hexdigest()

def seal(value):
    key = bytes.fromhex(read("keys", "receipt_key.json"))

    data = json.dumps(value, sort_keys=True).encode()

    return hmac.new(
        key,
        data,
        hashlib.sha256,
    ).hexdigest()


from Crypto.Cipher import DES, DES3
from Crypto.PublicKey import ECC, DSA
from Crypto.Protocol.DH import key_agreement
from Crypto.Signature import pkcs1_15

_original_setup = setup
_original_generate_signing_keys = generate_signing_keys
_original_sign_hash = sign_hash
_original_signature_values = signature_values
_original_encrypt_key = rsa_encrypt_key
_original_decrypt_key = rsa_decrypt_key
_original_search_token = search_token


def setup():
    _original_setup()
    if ALGORITHMS['key'] == 'ECDH' and not (BASE/'keys'/'ecdh_private.json').exists():
        key = ECC.generate(curve='P-256')
        print_crypto_parameters('ECDH key generation', {'Curve': 'P-256', 'Public key': key.public_key().export_key(format='PEM')})
        save('keys', 'ecdh_private.json', key.export_key(format='PEM'))
        save('keys', 'ecdh_public.json', key.public_key().export_key(format='PEM'))
    if ALGORITHMS['signature'] == 'Schnorr' and not (BASE/'keys'/'schnorr.json').exists():
        group = DSA.generate(2048)
        save('keys', 'schnorr.json', {name: int(getattr(group, name)) for name in ('p','q','g')})
    if ALGORITHMS['search'] == 'PKSE' and not (BASE/'keys'/'search_private.json').exists():
        key = RSA.generate(ALGORITHMS['rsa_bits']['search'])
        print_crypto_parameters('RSA search key generation', rsa_parameters(key))
        save('keys', 'search_private.json', key.export_key().decode())
        save('keys', 'search_public.json', key.publickey().export_key().decode())


def document_key():
    size = {'AES-128':16, 'AES-192':24, 'AES-256':32, 'DES':8, 'Triple-DES':24}[ALGORITHMS['encryption']]
    key = os.urandom(size)
    return DES3.adjust_key_parity(key) if ALGORITHMS['encryption'] == 'Triple-DES' else key


def document_cipher():
    return {'DES':DES, 'Triple-DES':DES3}.get(ALGORITHMS['encryption'], AES)





def cipher_modes():
    return ('CBC', 'ECB', 'CTR', 'EAX', 'GCM') if document_cipher() is AES else ('CBC', 'ECB', 'CTR', 'EAX')


def cipher_parameter_size(mode):
    block = document_cipher().block_size
    return {'ECB': 0, 'CBC': block, 'CTR': block // 2, 'EAX': block, 'GCM': 12}[mode]


def configured_cipher_options():
    settings = ALGORITHMS['cipher']
    source = settings['iv_source']
    iv = settings['iv_hex'] if source == 'manual' else ('00' * cipher_parameter_size(settings['mode']) if source == 'zero' else None)
    return {'mode': settings['mode'], 'padding': settings['padding'], 'iv': iv}


_used_cipher_parameters = set()


def aes_encrypt(plaintext, key, mode='CBC', iv=None, padding=None):
    algorithm = document_cipher()
    mode = mode.upper()
    if mode not in cipher_modes():
        raise ValueError('Unsupported cipher mode.')
    size = cipher_parameter_size(mode)
    padding = (padding or ('PKCS7' if mode in ('CBC', 'ECB') else 'NONE')).upper().replace('#', '')
    if padding not in ('PKCS7', 'NONE') or (mode not in ('CBC', 'ECB') and padding != 'NONE'):
        raise ValueError('Invalid padding for the selected mode.')
    if mode == 'ECB' and iv is not None:
        raise ValueError('ECB does not take an IV or nonce.')
    if isinstance(iv, str):
        if not re.fullmatch(r'[0-9a-fA-F]{' + str(size * 2) + '}', iv):
            raise ValueError('Invalid IV/nonce hexadecimal value or length.')
        iv = bytes.fromhex(iv)
    parameter = os.urandom(size) if iv is None else iv
    if not isinstance(parameter, bytes) or len(parameter) != size:
        raise ValueError(f'This mode requires a {size}-byte IV/nonce.')
    marker = (hashlib.sha256(key).digest(), mode, parameter)
    if mode != 'ECB' and marker in _used_cipher_parameters:
        raise ValueError('IV/nonce already used with this key; use a fresh value or key.')
    kwargs = {} if mode == 'ECB' else ({'iv': parameter} if mode == 'CBC' else {'nonce': parameter})
    cipher = algorithm.new(key, getattr(algorithm, 'MODE_' + mode), **kwargs)
    data = plaintext.encode('utf-8')
    metadata = {'version': 2, 'algorithm': ALGORITHMS['encryption'], 'mode': mode, 'parameter': parameter.hex(), 'padding': padding}
    if mode in ('CBC', 'ECB'):
        if padding == 'NONE' and len(data) % algorithm.block_size:
            raise ValueError('Padding is disabled: the complete UTF-8 payload must be a multiple of ' + str(algorithm.block_size) + ' bytes. Configure PKCS7 or a stream/authenticated mode in the generator.')
        ciphertext = cipher.encrypt(pad(data, algorithm.block_size) if padding == 'PKCS7' else data)
    elif mode in ('EAX', 'GCM'):
        ciphertext, tag = cipher.encrypt_and_digest(data)
        metadata['tag'] = tag.hex()
    else:
        ciphertext = cipher.encrypt(data)
    if mode != 'ECB':
        _used_cipher_parameters.add(marker)
    return metadata, ciphertext.hex()


def aes_decrypt(ciphertext, key, iv):
    algorithm = document_cipher()
    # Existing records stored just the CBC IV as a hexadecimal string.
    if isinstance(iv, str):
        mode, parameter, metadata = 'CBC', bytes.fromhex(iv), {}
    else:
        metadata = iv
        if metadata.get('version') != 2 or metadata.get('algorithm') != ALGORITHMS['encryption']:
            raise ValueError('Cipher configuration does not match this record.')
        mode, parameter = metadata['mode'], bytes.fromhex(metadata['parameter'])
    if mode not in cipher_modes() or len(parameter) != cipher_parameter_size(mode):
        raise ValueError('Invalid cipher mode or IV/nonce length.')
    kwargs = {} if mode == 'ECB' else ({'iv': parameter} if mode == 'CBC' else {'nonce': parameter})
    cipher = algorithm.new(key, getattr(algorithm, 'MODE_' + mode), **kwargs)
    data = bytes.fromhex(ciphertext)
    padding = metadata.get('padding', 'PKCS7' if mode in ('CBC', 'ECB') else 'NONE')
    if padding not in ('PKCS7', 'NONE') or (mode not in ('CBC', 'ECB') and padding != 'NONE'):
        raise ValueError('Invalid stored padding.')
    if mode in ('EAX', 'GCM'):
        plaintext = cipher.decrypt_and_verify(data, bytes.fromhex(metadata['tag']))
    else:
        plaintext = cipher.decrypt(data)
        if mode in ('CBC', 'ECB') and padding == 'PKCS7':
            plaintext = unpad(plaintext, algorithm.block_size)
    return plaintext.decode('utf-8')


def hash_message(message):
    return hashlib.new(ALGORITHMS['hash'].lower().replace('-', ''), message.encode()).hexdigest()


def rsa_encrypt_key(key, trace=None):
    if ALGORITHMS['key'] == 'RSA':
        return _original_encrypt_key(key)
    ephemeral = ECC.generate(curve='P-256')
    public = ECC.import_key(read('keys', 'ecdh_public.json'))
    secret = key_agreement(eph_priv=ephemeral, static_pub=public, kdf=lambda x: SHA256.new(x).digest())
    cipher = AES.new(secret, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(key)
    if trace is not None:
        trace.update({'ECDH curve': 'P-256', 'Ephemeral private scalar': int(ephemeral.d), 'Ephemeral public key': ephemeral.public_key().export_key(format='PEM'), 'Recipient public key': public.export_key(format='PEM'), 'Derived wrapping key (hex)': secret.hex()})
    return {'public':ephemeral.public_key().export_key(format='PEM'), 'nonce':cipher.nonce.hex(),
            'tag':tag.hex(), 'ciphertext':ciphertext.hex()}


def rsa_decrypt_key(ciphertext):
    if ALGORITHMS['key'] == 'RSA':
        return _original_decrypt_key(ciphertext)
    private = ECC.import_key(read('keys','ecdh_private.json'))
    public = ECC.import_key(ciphertext['public'])
    secret = key_agreement(static_priv=private, eph_pub=public, kdf=lambda x: SHA256.new(x).digest())
    cipher = AES.new(secret, AES.MODE_EAX, nonce=bytes.fromhex(ciphertext['nonce']))
    return cipher.decrypt_and_verify(bytes.fromhex(ciphertext['ciphertext']), bytes.fromhex(ciphertext['tag']))


def generate_signing_keys():
    if ALGORITHMS['signature'] == 'ElGamal':
        return _original_generate_signing_keys()
    if ALGORITHMS['signature'] == 'RSA':
        key = RSA.generate(ALGORITHMS['rsa_bits']['signature'])
        return key.export_key(), {'pem':key.publickey().export_key().decode()}
    group = read('keys','schnorr.json')
    private = secrets.randbelow(group['q']-1)+1
    return private, {**group, 'y':pow(group['g'],private,group['p'])}


def schnorr_challenge(digest, commitment, public):
    message = json.dumps([digest, commitment, public['p'], public['q'], public['g'], public['y']], separators=(',', ':'))
    return int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big') % public['q']


def sign_hash(digest, private, public, trace=None):
    if ALGORITHMS['signature'] == 'ElGamal':
        return _original_sign_hash(digest, private, public, trace)
    if ALGORITHMS['signature'] == 'RSA':
        return pkcs1_15.new(RSA.import_key(private)).sign(SHA256.new(bytes.fromhex(digest))).hex()
    nonce = secrets.randbelow(public['q']-1)+1
    commitment = pow(public['g'],nonce,public['p'])
    challenge = schnorr_challenge(digest,commitment,public)
    if trace is not None:
        trace.update({'Schnorr nonce k': nonce, 'Schnorr commitment': commitment, 'Schnorr challenge': challenge})
    return [challenge, (nonce+private*challenge) % public['q']]


def signature_values(digest, signature, public):
    if ALGORITHMS['signature'] == 'ElGamal':
        return _original_signature_values(digest, signature, public)
    if ALGORITHMS['signature'] == 'RSA':
        key = RSA.import_key(public['pem'])
        # PKCS#1 v1.5 SHA-256 DigestInfo, signing the selected document digest.
        info = bytes.fromhex('3031300d060960864801650304020105000420') + SHA256.new(bytes.fromhex(digest)).digest()
        size = key.size_in_bytes()
        expected = b'\x00\x01' + b'\xff'*(size-len(info)-3) + b'\x00' + info
        data = bytes.fromhex(signature)
        value = int.from_bytes(data,'big')
        if len(data) != size or value >= key.n:
            return expected.hex(), 'INVALID SIGNATURE'
        return expected.hex(), pow(value,key.e,key.n).to_bytes(size,'big').hex()
    challenge, response = signature
    if not (0 <= challenge < public['q'] and 0 <= response < public['q']):
        return 'VALID RANGE', 'INVALID SIGNATURE'
    commitment = pow(public['g'],response,public['p']) * pow(pow(public['y'],challenge,public['p']),-1,public['p']) % public['p']
    return challenge, schnorr_challenge(digest,commitment,public)


def search_token(value):
    if ALGORITHMS['search'] == 'SSE':
        return _original_search_token(value)
    return hashlib.sha256(value.encode()).hexdigest()


def index_token(value):
    token = search_token(value)
    if ALGORITHMS['search'] == 'SSE':
        return token
    public = RSA.import_key(read('keys','search_public.json'))
    return PKCS1_OAEP.new(public,hashAlgo=SHA256).encrypt(bytes.fromhex(token)).hex()


def stored_search_token(token):
    if ALGORITHMS['search'] == 'SSE':
        return token
    private = RSA.import_key(read('keys','search_private.json'))
    return PKCS1_OAEP.new(private,hashAlgo=SHA256).decrypt(bytes.fromhex(token)).hex()


def indexes_match(stored, expected):
    if isinstance(expected, dict):
        # Legacy text indexes stored only the exact-value token.
        if isinstance(stored, str) and set(expected) == {'exact', 'words'}:
            return hmac.compare_digest(stored_search_token(stored), stored_search_token(expected['exact']))
        return isinstance(stored, dict) and set(stored) == set(expected) and all(indexes_match(stored[k], expected[k]) for k in expected)
    if isinstance(expected, list):
        return isinstance(stored, list) and len(stored) == len(expected) and sorted(stored_search_token(x) for x in stored) == sorted(stored_search_token(x) for x in expected)
    return isinstance(stored, str) and hmac.compare_digest(stored_search_token(stored), stored_search_token(expected))

from decimal import Decimal, InvalidOperation


def record_filename(record_id):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", record_id):
        raise ValueError("Record ID must contain 1..40 letters, digits, underscores or hyphens.")
    return record_id + ".json"


def require(action):
    if ROLE not in ENTITIES or action not in ENTITIES[ROLE]:
        raise PermissionError("This entity cannot perform " + action)


def normalize_record(values):
    if set(values) != {field["name"] for field in DOMAIN["fields"]}:
        raise ValueError("Record fields do not match the configured schema.")
    result = {}
    for field in DOMAIN["fields"]:
        name, kind = field["name"], field["type"]
        value = str(values[name]).strip()
        if not value:
            raise ValueError(name + " cannot be empty.")
        if kind == "text":
            result[name] = value
        elif kind == "choice":
            matches = [option for option in field["choices"] if option.casefold() == value.casefold()]
            if not matches:
                raise ValueError(name + ": choose " + ", ".join(field["choices"]))
            result[name] = matches[0]
        else:
            if len(value) > 80 or not re.fullmatch(r"[+]?[0-9]+(?:[.][0-9]+)?", value):
                raise ValueError(name + ": use nonnegative digits with an optional decimal point (no exponent notation).")
            try:
                number = Decimal(value)
                scale = field.get("decimals", 0)
                if not number.is_finite() or number < 0 or number > Decimal(10**18) / (10**scale):
                    raise ValueError(name + ": use a finite nonnegative number within the allowed range.")
                units = number * (10**scale)
                if units != units.to_integral_value():
                    raise ValueError(name + f": use at most {scale} decimal places.")
                result[name] = int(number) if kind == "integer" else format(number, f".{scale}f")
            except InvalidOperation as exc:
                raise ValueError(name + ": invalid number.") from exc
    return result


def metric_values(record):
    values = {}
    for name, metric in METRICS.items():
        if metric["kind"] == "record_count":
            values[name] = 1
        elif metric["kind"] == "count":
            values[name] = int(record[metric["field"]] == metric["choice"])
        else:
            values[name] = int(Decimal(str(record[metric["field"]])) * metric["scale"])
    return values


def search_words(value):
    return sorted(set(re.findall(r'\w+', str(value).casefold())))

def make_index(record, timestamp):
    result = {}
    for field in DOMAIN['fields']:
        if not field['search']:
            continue
        name = field['name']
        exact = index_token(name + ':' + str(record[name]).casefold())
        if field['type'] == 'text':
            result[name] = {'exact': exact, 'words': [index_token('word:' + name + ':' + word) for word in search_words(record[name])]}
        else:
            result[name] = exact
    result['__minute__'] = index_token('minute:' + timestamp[:16])
    return result


def record_files(filename):
    return {folder: read(folder, filename) for folder in (
        "encrypted", "encrypted_key", "iv", "hashes", "signature",
        "public_key", "paillier", "metadata", "index")}


def valid_receipt(filename):
    return hmac.compare_digest(read("receipts", filename), seal(record_files(filename)))


def submit_record(record_id, values, cipher_options=None):
    require("submit_record")
    EVENTS.clear()
    filename = record_filename(record_id)
    if (BASE / "metadata" / filename).exists():
        raise ValueError("Record ID already exists; use a new ID for a new record.")
    if DOMAIN["close_on_aggregate"] and (BASE / "tally" / "aggregate.json").exists():
        raise ValueError("Submissions closed when the aggregate was created.")
    record = normalize_record(values)
    serialized = json.dumps({"record": record, "record_id": record_id, "submitted_by": ROLE, "signed_by": ROLE}, sort_keys=True, ensure_ascii=False)
    digest = timed("Hashing", hash_message, serialized)
    private_key, public_key = generate_signing_keys()
    signing_trace = {}
    signature = timed("Signing", sign_hash, digest, private_key, public_key, signing_trace)
    n = read("keys", "paillier_public.json")["n"]
    encrypted, randomness = {}, {}
    for name, value in metric_values(record).items():
        encrypted[name], randomness[name] = timed("Paillier encryption", paillier_encrypt, value, n)
    payload = json.dumps({"record": record, "randomness": randomness}, ensure_ascii=False)
    key = document_key()
    options = configured_cipher_options() if cipher_options is None else cipher_options
    if set(options) - {"mode", "iv", "padding"}:
        raise ValueError("Unknown cipher option.")
    iv, ciphertext = timed(ALGORITHMS["encryption"] + " encryption", aes_encrypt, payload, key, options.get("mode", "CBC"), options.get("iv"), options.get("padding"))
    wrapping_trace = {}
    wrapped = timed(ALGORITHMS["key"] + " key encryption", rsa_encrypt_key, key, wrapping_trace)
    timestamp = now()
    settings = read("keys", "settings.json")
    if not settings["start"] <= timestamp <= settings["deadline"]:
        raise ValueError("Outside the submission period.")
    files = {"encrypted": ciphertext, "encrypted_key": wrapped, "iv": iv,
             "hashes": digest, "signature": signature, "public_key": public_key,
             "paillier": encrypted, "metadata": {"version": 2, "submitted_at": timestamp, "submitted_by": ROLE, "signed_by": ROLE, "signature_algorithm": ALGORITHMS["signature"]},
             "index": make_index(record, timestamp)}
    for folder, value in files.items():
        save(folder, filename, value)
    save("receipts", filename, seal(record_files(filename)))
    submission_parameters(key, iv, ciphertext, digest, private_key, public_key,
                          signature, wrapped, encrypted, randomness, signing_trace, wrapping_trace)
    show_summary("Submit " + DOMAIN["record_name"], {"Record ID": record_id,
        "Submitted by": ROLE, "Cipher": ALGORITHMS["encryption"],
        "Submitted at IST": timestamp, "Result": "SUBMITTED"})
    return True


def check_record(record_id):
    # Internal verification pipeline; exposed only through permission-checked functions.
    filename = record_filename(record_id)
    if not valid_receipt(filename):
        raise ValueError("Receipt mismatch: stored record or metadata was changed.")
    stored_hash = read("hashes", filename)
    signature = read("signature", filename)
    public_key = read("public_key", filename)
    key = timed(ALGORITHMS["key"] + " key decryption", rsa_decrypt_key, read("encrypted_key", filename))
    payload = json.loads(timed(ALGORITHMS["encryption"] + " decryption", aes_decrypt, read("encrypted", filename), key, read("iv", filename)))
    record = normalize_record(payload["record"])
    metadata = read("metadata", filename)
    signed_data = ({"record": record, "record_id": record_id,
                    "submitted_by": metadata["submitted_by"], "signed_by": metadata["signed_by"], "submitted_at": metadata["submitted_at"]}
                   if metadata.get("version") == 3 else record)
    serialized = json.dumps(signed_data, sort_keys=True, ensure_ascii=False)
    computed_hash = timed("Hashing", hash_message, serialized)
    hash_valid = timed("Hash verification", hmac.compare_digest, stored_hash, computed_hash)
    signature_valid = timed("Signature verification", verify_signature, computed_hash, signature, public_key)
    expected, actual = signature_values(computed_hash, signature, public_key)
    timestamp = read("metadata", filename)["submitted_at"]
    datetime.strptime(timestamp, TIME_FORMAT)
    settings = read("keys", "settings.json")
    valid_time = settings["start"] <= timestamp <= settings["deadline"] and timestamp <= now()
    details = {"Record ID": record_id, "Stored " + ALGORITHMS["hash"]: stored_hash, "Computed " + ALGORITHMS["hash"]: computed_hash,
               "Hash comparison": "MATCH" if hash_valid else "MISMATCH", ALGORITHMS["signature"] + " signature": signature,
               "Expected verification value": expected, "Actual verification value": actual,
               "Signature comparison": "MATCH" if signature_valid else "MISMATCH", "Timestamp valid": valid_time}
    if not (hash_valid and signature_valid and valid_time):
        show_summary("Verify " + DOMAIN["record_name"], {**details, "Result": "REJECTED"})
        raise ValueError("Verification failed.")
    n = read("keys", "paillier_public.json")["n"]
    encrypted = read("paillier", filename)
    if set(encrypted) != set(METRICS) or set(payload["randomness"]) != set(METRICS):
        raise ValueError("Encrypted metric schema mismatch.")
    for name, value in metric_values(record).items():
        r = payload["randomness"][name]
        if not 0 < r < n or gcd(r, n) != 1:
            raise ValueError("Invalid Paillier randomness.")
        if encrypted[name] != pow(n + 1, value, n*n) * pow(r, n, n*n) % (n*n):
            raise ValueError("Encrypted total does not match the signed record.")
    if not indexes_match(read("index", filename), make_index(record, timestamp)):
        raise ValueError("Search index mismatch.")
    return record, details


def verify_record(record_id):
    require("verify_record")
    EVENTS.clear()
    record_access(record_id)
    _, details = check_record(record_id)
    filename = record_filename(record_id)
    save("verified", filename, {"verified_at": now(), "receipt": read("receipts", filename)})
    show_summary("Verify " + DOMAIN["record_name"], {**details, "Result": "ACCEPTED"})
    return True


def view_record(record_id):
    require('view_record')
    EVENTS.clear()
    return display_record(record_id, 'all')


def find_records(field_name=None, query=None, start=None, end=None):
    require('search_records')
    EVENTS.clear()
    tokens = set()
    words = None
    if field_name is not None:
        field = next((f for f in DOMAIN['fields'] if f['name'] == field_name and f['search']), None)
        if field is None:
            raise ValueError('This field is not searchable.')
        if field['type'] == 'text':
            words = search_words(query)
            if not words:
                raise ValueError('Enter at least one search word.')
            tokens = {search_token('word:' + field_name + ':' + word) for word in words}
        else:
            if field['type'] == 'integer':
                query = str(int(query))
            elif field['type'] == 'decimal':
                number = Decimal(str(query))
                if not number.is_finite() or number * 10**field['decimals'] != (number * 10**field['decimals']).to_integral_value():
                    raise ValueError('Invalid decimal query precision.')
                query = format(number, f".{field['decimals']}f")
            tokens.add(search_token(field_name + ':' + str(query).strip().casefold()))
        index_field = field_name
    else:
        start_time = datetime.strptime(start, TIME_FORMAT)
        end_time = datetime.strptime(end, TIME_FORMAT)
        if end_time < start_time or end_time - start_time > timedelta(days=7):
            raise ValueError('Use an ordered time range of at most seven days.')
        minute = start_time.replace(second=0)
        while minute <= end_time:
            tokens.add(search_token('minute:' + minute.strftime('%Y-%m-%d %H:%M')))
            minute += timedelta(minutes=1)
        index_field = '__minute__'
    matches = []
    for file in sorted((BASE / 'index').glob('*.json')):
        if not valid_receipt(file.name):
            continue
        stored = read('index', file.name).get(index_field)
        if words is not None:
            if isinstance(stored, dict):
                indexed_words = {stored_search_token(token) for token in stored['words']}
                if not tokens.issubset(indexed_words):
                    continue
            else:
                # Older records contain only whole-field tokens. Verify/decrypt
                # internally for compatibility; do not alter their signed files.
                record, _ = check_record(file.stem)
                if not set(words).issubset(search_words(record[field_name])):
                    continue
        elif stored_search_token(stored) not in tokens:
            continue
        if field_name is None:
            timestamp = datetime.strptime(read('metadata', file.name)['submitted_at'], TIME_FORMAT)
            if not start_time <= timestamp <= end_time:
                continue
        matches.append(file.stem)
    show_summary('Search', {'Matching record IDs': matches})
    return matches


def search_records():
    require("search_records")
    fields = [f for f in DOMAIN["fields"] if f["search"]]
    for number, field in enumerate(fields, 1):
        print(f"{number}. {field['name']}")
    print(f"{len(fields)+1}. Submission time range")
    choice = int(input("Search by: "))
    if 1 <= choice <= len(fields):
        field = fields[choice-1]
        return find_records(field["name"], input("Word(s), all must match: " if field["type"] == "text" else "Exact value: "))
    if choice == len(fields)+1:
        print("Use YYYY-MM-DD HH:MM:SS, IST.")
        return find_records(start=input("Start: ").strip(), end=input("End: ").strip())
    raise ValueError("Invalid search selection.")


def build_aggregate(record_ids=None):
    n = read("keys", "paillier_public.json")["n"]
    totals = {name: 1 for name in METRICS}
    receipts = {}
    if record_ids is None:
        record_ids = [file.stem for file in sorted((BASE / "receipts").glob("*.json"))]
    if len(set(record_ids)) != len(record_ids):
        raise ValueError("Duplicate record IDs in aggregate.")
    for record_id in sorted(record_ids):
        record_access(record_id)
        file = BASE / "verified" / record_filename(record_id)
        if not file.exists():
            raise ValueError("Verify selected record first: " + record_id)
        if not valid_receipt(file.name):
            raise ValueError("Accepted record changed: " + file.stem)
        receipt = read("receipts", file.name)
        if read("verified", file.name)["receipt"] != receipt:
            raise ValueError("Record must be verified again.")
        receipts[file.stem] = receipt
        encrypted = read("paillier", file.name)
        if set(encrypted) != set(METRICS):
            raise ValueError("Metric schema mismatch.")
        for name in METRICS:
            if type(encrypted[name]) is not int or not 0 < encrypted[name] < n*n or gcd(encrypted[name], n) != 1:
                raise ValueError("Invalid or incompatible Paillier ciphertext.")
            totals[name] = totals[name] * encrypted[name] % (n*n)
    count = len(receipts)
    if count < DOMAIN["min_records"]:
        raise ValueError(f"Verify at least {DOMAIN['min_records']} records first.")
    if count * 10**18 >= n:
        raise ValueError("Aggregate could overflow the Paillier plaintext range.")
    return {"ciphertexts": totals, "records": receipts}


def aggregate_records():
    require("aggregate_records")
    EVENTS.clear()
    aggregate = timed("Homomorphic aggregation", build_aggregate, selected_records())
    save("tally", "aggregate.json", aggregate)
    save("tally", "aggregate_seal.json", seal(aggregate))
    show_summary("Aggregate", {"Included record IDs": list(aggregate["records"]),
                              "Paillier public parameters": read("keys", "paillier_public.json"),
                              "Encrypted totals": {METRICS[name]["label"]: value for name, value in aggregate["ciphertexts"].items()},
                              "Submissions closed": DOMAIN["close_on_aggregate"]})
    return aggregate


def threshold_decrypt():
    require("threshold_decrypt")
    EVENTS.clear()
    aggregate = read("tally", "aggregate.json")
    aggregate_seal = read("tally", "aggregate_seal.json")
    if not hmac.compare_digest(seal(aggregate), aggregate_seal):
        raise ValueError("Aggregate was changed.")
    if aggregate != build_aggregate(list(aggregate["records"])):
        raise ValueError("Aggregate is stale. Reverify and re-aggregate the selected records.")
    n = read("keys", "paillier_public.json")["n"]
    partials = []
    for number in (1, 2):
        share = timed(f"Authority {number} authentication", unlock_share, number,
                      getpass(f"Authority {number} password: "))
        partial = {name: timed(f"Authority {number} partial decryption", pow, value, share, n*n)
                   for name, value in aggregate["ciphertexts"].items()}
        partials.append(partial)
        del share
    raw_results, results = {}, {}
    for name, metric in METRICS.items():
        combined = partials[0][name] * partials[1][name] % (n*n)
        if (combined-1) % n:
            raise ValueError("Invalid combined partial decryption.")
        value = ((combined-1)//n) % n
        raw_results[name] = value
        results[metric["label"]] = (format(Decimal(value) / metric["scale"], f".{metric['decimals']}f")
                                   if metric["scale"] != 1 else value)
    if raw_results["record_count"] != len(aggregate["records"]):
        raise ValueError("Aggregate record count mismatch.")
    for field in DOMAIN["fields"]:
        names = [name for name, metric in METRICS.items() if metric.get("field") == field["name"] and metric["kind"] == "count"]
        if names and sum(raw_results[name] for name in names) != len(aggregate["records"]):
            raise ValueError("Category count mismatch.")
    save_encrypted_results(results)
    show_summary("Threshold decrypt aggregate", results)
    return results


def entity_menu(entity):
    if ROLE != entity or entity not in ENTITIES:
        raise PermissionError('Wrong entity session.')
    names = [action for action in DOMAIN_ACTIONS if action in ENTITIES[entity] and action != 'access_all_records']
    while True:
        print('\n------ ' + entity + ' ------')
        for number, action in enumerate(names, 1):
            print(f'{number}. {DOMAIN_ACTIONS[action]}')
        print(f'{len(names) + 1}. Logout')
        choice = input('Enter choice: ').strip()
        if choice in ('0', str(len(names) + 1)):
            return
        try:
            if not choice.isdigit() or not 1 <= int(choice) <= len(names):
                raise ValueError('Invalid option number.')
            action = names[int(choice) - 1]
            require(action)
            if action == 'submit_record':
                record_id = input(DOMAIN['record_name'] + ' ID: ').strip()
                values = {}
                for field in DOMAIN['fields']:
                    suffix = ' (' + ', '.join(field['choices']) + ')' if field['type'] == 'choice' else ''
                    values[field['name']] = input(field['name'] + suffix + ': ')
                submit_record(record_id, values)
            elif action in ('verify_record', 'view_record', 'view_text', 'view_amounts', 'view_ciphertext', 'view_signature', 'view_metadata'):
                globals()[action](input(DOMAIN['record_name'] + ' ID: ').strip())
            elif action == 'select_records':
                select_records([x.strip() for x in input('Record IDs, comma separated: ').split(',')])
            elif action in ('rsa_multiply', 'elgamal_multiply', 'compare_demo'):
                label = 'First integer (0 or greater): ' if action == 'rsa_multiply' else 'First integer (1 or greater): '
                globals()[action](int(input(label)), int(input('Second integer: ')))
            else:
                globals()[action]()
        except (OSError, ValueError, KeyError, TypeError, IndexError, PermissionError, InvalidOperation, OverflowError) as error:
            print('Operation stopped:', error)


def has_permission(action):
    return ROLE in ENTITIES and action in ENTITIES[ROLE]


def record_access(record_id):
    filename = record_filename(record_id)
    if ROLE not in ENTITIES:
        raise PermissionError('Log in first.')
    if not valid_receipt(filename):
        raise ValueError('Record receipt mismatch.')
    metadata = read('metadata', filename)
    # Operation handlers authorize access. Ownership limits only the explicit
    # "my records/signatures" operations, as the original cross-role flow requires.
    return metadata


def signature_status(record_id):
    filename = record_filename(record_id)
    path = BASE / 'verified' / filename
    if not path.exists():
        return 'Not yet verified'
    return 'Previously verified; receipt unchanged' if read('verified', filename).get('receipt') == read('receipts', filename) else 'Needs verification again'


def display_record(record_id, fields=None):
    metadata = record_access(record_id)
    result = {'Record ID': record_id, 'Submitted by': metadata.get('submitted_by', 'Unknown (legacy)'),
              'Submitted at': metadata['submitted_at'], 'Signature status': signature_status(record_id)}
    allowed = []
    for field in DOMAIN['fields']:
        permission = 'view_amounts' if field['type'] in ('integer', 'decimal') else 'view_text'
        if fields == 'all' or (fields is None and has_permission(permission)) or fields == permission:
            allowed.append(field['name'])
    if allowed:
        record, _ = check_record(record_id)
        result['Fields'] = {name: record[name] for name in allowed}
    show_summary('View ' + DOMAIN['record_name'], result)
    return result





def view_text(record_id):
    require('view_text')
    EVENTS.clear()
    return display_record(record_id, 'view_text')


def view_amounts(record_id):
    require('view_amounts')
    EVENTS.clear()
    return display_record(record_id, 'view_amounts')


def list_records(own=False):
    require('view_own_records' if own else 'view_all_records')
    EVENTS.clear()
    results = []
    for file in sorted((BASE / 'metadata').glob('*.json')):
        metadata = read('metadata', file.name)
        if own and metadata.get('submitted_by') != ROLE:
            continue
        results.append(display_record(file.stem, 'all' if own or has_permission('view_record') else None))
    if not results:
        print('No records available.')
    return results


def view_all_records():
    return list_records()


def view_own_records():
    return list_records(own=True)


def signature_details(record_id):
    metadata = record_access(record_id)
    filename = record_filename(record_id)
    return {'Record ID': record_id, 'Signer': metadata.get('signed_by', 'Unknown (legacy)'),
            'Algorithm': metadata.get('signature_algorithm', ALGORITHMS['signature']),
            'Status': signature_status(record_id), 'Signature': read('signature', filename)}


def view_signature(record_id):
    require('view_signature')
    EVENTS.clear()
    result = signature_details(record_id)
    show_summary('View existing signature (does not verify)', result)
    return result


def view_own_signatures():
    require('view_own_signatures')
    EVENTS.clear()
    result = []
    for file in sorted((BASE / 'metadata').glob('*.json')):
        if read('metadata', file.name).get('signed_by') == ROLE:
            details = signature_details(file.stem)
            show_summary('My existing signature (does not verify)', details)
            result.append(details)
    if not result:
        print('No signatures created by this identity.')
    return result


def view_ciphertext(record_id):
    require('view_ciphertext')
    EVENTS.clear()
    metadata = record_access(record_id)
    filename = record_filename(record_id)
    ciphertext = read('encrypted', filename)
    result = {'Record ID': record_id, 'Ciphertext hex': ciphertext,
              'Ciphertext bytes': len(bytes.fromhex(ciphertext))}
    if metadata.get('submitted_by') == ROLE:
        key = rsa_decrypt_key(read('encrypted_key', filename))
        label = 'AES' if ALGORITHMS['encryption'].startswith('AES') else ALGORITHMS['encryption']
        result[label + ' key (hex)'] = key.hex()
    show_summary('View ciphertext', result)
    return result


def view_aggregate_ciphertext():
    require('view_aggregate_ciphertext')
    EVENTS.clear()
    aggregate = read('tally', 'aggregate.json')
    if not hmac.compare_digest(seal(aggregate), read('tally', 'aggregate_seal.json')):
        raise ValueError('Aggregate was changed.')
    if aggregate != build_aggregate(list(aggregate['records'])):
        raise ValueError('Aggregate is stale.')
    result = {'Included IDs': list(aggregate['records']),
              'Paillier public parameters': read('keys', 'paillier_public.json'),
              'Encrypted totals (hex)': {METRICS[k]['label']: hex(v) for k, v in aggregate['ciphertexts'].items()}}
    show_summary('View encrypted Paillier aggregate; no decryption', result)
    return result


def select_records(record_ids):
    require('select_records')
    EVENTS.clear()
    if not isinstance(record_ids, (list, tuple)) or not record_ids or len(set(record_ids)) != len(record_ids):
        raise ValueError('Select a nonempty list of unique record IDs.')
    for record_id in record_ids:
        record_access(record_id)
    selection = {'records': sorted(record_ids), 'selected_by': ROLE, 'selected_at': now()}
    save('tally', 'selection.json', selection)
    save('tally', 'selection_seal.json', seal(selection))
    show_summary('Select records', {'Selected IDs': selection['records']})
    return selection['records']


def selected_records():
    if not (BASE / 'tally' / 'selection.json').exists():
        return None
    selection = read('tally', 'selection.json')
    if not hmac.compare_digest(seal(selection), read('tally', 'selection_seal.json')):
        raise ValueError('Selection has been changed.')
    return selection['records']


def verify_selected():
    require('verify_selected')
    EVENTS.clear()
    ids = selected_records()
    if not ids:
        raise ValueError('No records selected. Use Select records first.')
    for record_id in ids:
        record_access(record_id)
        check_record(record_id)
    for record_id in ids:
        filename = record_filename(record_id)
        save('verified', filename, {'verified_at': now(), 'receipt': read('receipts', filename)})
    show_summary('Verify selected records', {'Verified IDs': ids, 'Result': 'ACCEPTED'})
    return ids


def save_encrypted_results(results):
    key = document_key()
    metadata, ciphertext = aes_encrypt(json.dumps(results), key, mode='EAX')
    save('tally', 'final_totals.json', {'completed_at': now(), 'encrypted': ciphertext,
                                     'iv': metadata, 'encrypted_key': rsa_encrypt_key(key)})


def rsa_multiply(left, right):
    require('rsa_multiply')
    EVENTS.clear()
    key = RSA.generate(ALGORITHMS['rsa_bits']['key'])
    if any(type(x) is not int or not 0 <= x < key.n for x in (left, right)):
        raise ValueError('Use integer representatives from 0 to n-1.')
    c1, c2 = pow(left, key.e, key.n), pow(right, key.e, key.n)
    combined = c1 * c2 % key.n
    recovered = pow(combined, key.d, key.n)
    expected = left * right % key.n
    if recovered != expected:
        raise ValueError('RSA multiplication check failed.')
    result = {'Algorithm': 'RSA multiplication without OAEP padding', **rsa_parameters(key, include_private=True),
              'First plaintext': left, 'Second plaintext': right, 'First ciphertext': c1, 'Second ciphertext': c2,
              'Ciphertext product': combined, 'Decrypted product modulo n': recovered,
              'Expected product modulo n': expected}
    show_summary('RSA homomorphic multiplication', result)
    return recovered


def elgamal_encrypt_number(value, public, trace=None):
    p, g, y = public['p'], public['g'], public['y']
    if type(value) is not int or not 1 <= value < p:
        raise ValueError('ElGamal requires an integer from 1 to p-1.')
    nonce = secrets.randbelow(p - 2) + 1
    if trace is not None:
        trace['Random exponent k'] = nonce
    return [pow(g, nonce, p), value * pow(y, nonce, p) % p]


def elgamal_decrypt_number(ciphertext, private, public):
    p = public['p']
    if len(ciphertext) != 2 or any(type(x) is not int or not 1 <= x < p for x in ciphertext):
        raise ValueError('Invalid ElGamal ciphertext.')
    return ciphertext[1] * pow(pow(ciphertext[0], private, p), -1, p) % p


def elgamal_demo(left, right, compare=False):
    require('compare_demo' if compare else 'elgamal_multiply')
    EVENTS.clear()
    private, public = _original_generate_signing_keys()
    trace1, trace2 = {}, {}
    c1 = elgamal_encrypt_number(left, public, trace1)
    c2 = elgamal_encrypt_number(right, public, trace2)
    print_crypto_parameters('ElGamal encryption parameters', {**public, 'Private x': private,
                            'First random k': trace1['Random exponent k'], 'Second random k': trace2['Random exponent k'],
                            'First ciphertext': c1, 'Second ciphertext': c2})
    if compare:
        a = elgamal_decrypt_number(c1, private, public)
        b = elgamal_decrypt_number(c2, private, public)
        value = '<' if a < b else '>' if a > b else '='
        show_summary('Compare plaintexts after ElGamal decryption', {'First recovered value': a, 'Second recovered value': b, 'Result': value})
        return value
    combined = [c1[i] * c2[i] % public['p'] for i in (0, 1)]
    value = elgamal_decrypt_number(combined, private, public)
    if value != left * right % public['p']:
        raise ValueError('ElGamal multiplication check failed.')
    show_summary('ElGamal homomorphic multiplication', {'Modulus p': public['p'],
                 'Combined ciphertext': combined, 'Decrypted product modulo p': value})
    return value


def elgamal_multiply(left, right):
    return elgamal_demo(left, right)


def compare_demo(left, right):
    return elgamal_demo(left, right, compare=True)


def access_all_records():
    require('access_all_records')
    print('Compatibility setting: each assigned operation already has its stated record scope.')


def view_metadata(record_id):
    require('view_metadata')
    EVENTS.clear()
    return display_record(record_id, 'metadata')




def print_crypto_parameters(operation, parameters):
    # Console only: never copy secret keys into the shared event log or records.
    timestamp = datetime.now(IST).isoformat(timespec='milliseconds')
    print(f'\n[{timestamp}] {ROLE or "SETUP"} - {operation}')
    for name, value in parameters.items():
        print(str(name) + ':', value)


def rsa_parameters(key, include_private=False):
    result = {'RSA key bits': key.size_in_bits(), 'RSA n': int(key.n), 'RSA e': int(key.e)}
    if include_private:
        result.update({'RSA d (private)': int(key.d), 'RSA p (private)': int(key.p),
                       'RSA q (private)': int(key.q), 'RSA u = p^-1 mod q (private)': int(key.u)})
    return result


def submission_parameters(key, iv, ciphertext, digest, private, public, signature, wrapped, encrypted, randomness, signing_trace, wrapping_trace):
    # Show the signature and public verification parameters, never private signing material.
    parameters = {'Hash algorithm': ALGORITHMS['hash'], 'Document digest': digest,
                  'Signature algorithm': ALGORITHMS['signature']}
    if ALGORITHMS['signature'] == 'RSA':
        public_key = RSA.import_key(public['pem'])
        parameters.update(rsa_parameters(public_key))
        parameters['RSA signature encoding'] = 'PKCS#1 v1.5 with SHA-256 over the document digest bytes'
        parameters['RSA signing SHA-256 digest'] = SHA256.new(bytes.fromhex(digest)).hexdigest()
    else:
        parameters.update({f'Signing public {name}': value for name, value in public.items()})
    parameters['Digital signature'] = signature
    print_crypto_parameters('Hashing and digital signature parameters', parameters)

    label = 'AES' if ALGORITHMS['encryption'].startswith('AES') else ALGORITHMS['encryption']
    parameters = {label + ' key (hex)': key.hex(), 'Ciphertext (hex)': ciphertext}
    if iv['mode'] == 'CBC':
        parameters['IV (hex)'] = iv['parameter']
    elif iv['mode'] != 'ECB':
        parameters['Nonce (hex)'] = iv['parameter']
    if 'tag' in iv:
        parameters['Authentication tag (hex)'] = iv['tag']
    print_crypto_parameters('Document encryption parameters', parameters)

    parameters = {'Key protection algorithm': ALGORITHMS['key'], 'Encrypted document key': wrapped}
    if ALGORITHMS['key'] == 'RSA':
        parameters.update(rsa_parameters(RSA.import_key(read('keys', 'rsa_public.json'))))
        parameters['Encryption encoding'] = 'RSA-OAEP; SHA-256; MGF1-SHA-256; empty label'
    elif ALGORITHMS['key'] == 'ECDH':
        parameters.update({name: value for name, value in wrapping_trace.items()
                           if 'public key' in name.lower() or 'public' in name.lower() or 'curve' in name.lower()})
    print_crypto_parameters('Document key protection parameters', parameters)

    if not ALGORITHMS['show_paillier_on_submit']:
        return
    n = read('keys', 'paillier_public.json')['n']
    parameters = {'Paillier n': n, 'Paillier g': n + 1, 'Paillier n squared': n*n}
    for name, value in encrypted.items():
        label = METRICS[name]['label']
        parameters[label + ' randomness r'] = randomness[name]
        parameters[label + ' ciphertext'] = value
    print_crypto_parameters('Paillier encryption parameters', parameters)

def main():
    global ROLE
    setup()
    names = list(ENTITIES)
    while True:
        print("\n" + DOMAIN["title"])
        for number, name in enumerate(names, 1):
            print(f"{number}. {name}")
        print(f"{len(names)+1}. Exit")
        choice = input("Enter choice: ").strip()
        if choice == str(len(names)+1):
            break
        if not choice.isdigit() or not 1 <= int(choice) <= len(names):
            print("Invalid choice.")
            continue
        entity = names[int(choice)-1]
        try:
            if login(entity):
                ROLE = entity
                entity_menu(entity)
        except (OSError, ValueError, KeyError, TypeError, IndexError, PermissionError, InvalidOperation) as error:
            print("Operation stopped:", error)
        finally:
            ROLE = None



NETWORK = {'host': '127.0.0.1', 'port': 5000}
# Network adapter: bounded length-prefixed JSON; no pickle or eval.
import socket
import struct
import ssl
import sys

MAX_MESSAGE = 2 * 1024 * 1024


def recv_exact(connection, length):
    parts = bytearray()
    while len(parts) < length:
        chunk = connection.recv(length - len(parts))
        if not chunk:
            raise ConnectionError('Connection closed.')
        parts.extend(chunk)
    return bytes(parts)


def receive_message(connection):
    length = struct.unpack('!I', recv_exact(connection, 4))[0]
    if not 0 < length <= MAX_MESSAGE:
        raise ValueError('Invalid message size.')
    value = json.loads(recv_exact(connection, length).decode('utf-8'),
                       parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Invalid JSON constant.')))
    if not isinstance(value, dict):
        raise ValueError('Expected a JSON object.')
    return value


def send_message(connection, value):
    data = json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')
    if len(data) > MAX_MESSAGE:
        raise ValueError('Response too large; select fewer records.')
    connection.sendall(struct.pack('!I', len(data)) + data)


def signed_record(record_id, record, identity, timestamp):
    return json.dumps({'record': record, 'record_id': record_id,
                       'submitted_by': identity, 'signed_by': identity,
                       'submitted_at': timestamp}, sort_keys=True, ensure_ascii=False)


def concise(value):
    if isinstance(value, dict):
        return {k: concise(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [concise(v) for v in value]
    text = str(value)
    return text[:96] + '... (' + str(len(text)) + ' characters)' if len(text) > 160 else value


def show_summary(action, details):
    for name, value in details.items():
        # Existing demonstration handlers may include private ephemeral values.
        if 'private' not in name.lower() and 'key (hex)' not in name.lower() and 'public parameters' not in name.lower():
            print(str(name) + ':', concise(value))


def print_crypto_parameters(operation, parameters):
    pass  # Suppress legacy key dumps in network mode only.
import builtins
import contextlib
import io

_disk_read = read
_disk_save = save
_pending = {}


def read(folder, filename):
    if (folder, filename) in _pending:
        return _pending[(folder, filename)]
    return _disk_read(folder, filename)


def save(folder, filename, value):
    path = BASE / folder / filename
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
    os.replace(temporary, path)


def enrolled_signer(identity, public):
    if not isinstance(public, dict):
        raise ValueError('Invalid signing key.')
    if ALGORITHMS['signature'] == 'RSA':
        key = RSA.import_key(public['pem'])
        if key.has_private() or key.size_in_bits() != ALGORITHMS['rsa_bits']['signature'] or key.e != 65537:
            raise ValueError('Invalid RSA signing public key.')
    else:
        group = read('keys', 'elgamal.json' if ALGORITHMS['signature'] == 'ElGamal' else 'schnorr.json')
        if set(public) != set(group) | {'y'} or any(public[k] != v for k, v in group.items()):
            raise ValueError('Signing group mismatch.')
        if type(public['y']) is not int or not 1 < public['y'] < group['p']:
            raise ValueError('Invalid signing public key.')
    path = BASE / 'keys' / 'signers.json'
    known = read('keys', 'signers.json') if path.exists() else {}
    if identity in known and known[identity] != public:
        raise PermissionError('Signing key differs from the enrolled identity key.')
    return known


def accept_submission(bundle):
    require('submit_record')
    if not isinstance(bundle, dict) or set(bundle) != {'record_id', 'files'}:
        raise ValueError('Invalid submission structure.')
    record_id, files = bundle['record_id'], bundle['files']
    filename = record_filename(record_id)
    expected = {'encrypted', 'encrypted_key', 'iv', 'hashes', 'signature', 'public_key', 'paillier', 'metadata'}
    if not isinstance(files, dict) or set(files) != expected:
        raise ValueError('Invalid submission fields.')
    if (BASE / 'receipts' / filename).exists():
        raise ValueError('Record ID already exists.')
    if DOMAIN['close_on_aggregate'] and (BASE / 'tally' / 'aggregate.json').exists():
        raise ValueError('Submissions closed after aggregation.')
    metadata = files['metadata']
    if not isinstance(metadata, dict) or set(metadata) != {'version', 'submitted_at', 'submitted_by', 'signed_by', 'signature_algorithm'}:
        raise ValueError('Invalid metadata.')
    if metadata['version'] != 3 or metadata['submitted_by'] != ROLE or metadata['signed_by'] != ROLE or metadata['signature_algorithm'] != ALGORITHMS['signature']:
        raise PermissionError('Submission identity mismatch.')
    timestamp = metadata['submitted_at']
    submitted = datetime.strptime(timestamp, TIME_FORMAT)
    received = now()
    settings = read('keys', 'settings.json')
    if not settings['start'] <= timestamp <= settings['deadline'] or not settings['start'] <= received <= settings['deadline']:
        raise ValueError('Outside the submission period.')
    # Client time is a signed assertion, not a trusted timestamp.
    if abs((datetime.strptime(received, TIME_FORMAT) - submitted).total_seconds()) > 300:
        raise ValueError('Client timestamp differs from server time by more than five minutes.')
    known = enrolled_signer(ROLE, files['public_key'])
    iv = files['iv']
    if not isinstance(iv, dict) or iv.get('mode') != ALGORITHMS['cipher']['mode'] or iv.get('padding') != ALGORITHMS['cipher']['padding']:
        raise ValueError('Cipher settings differ from generated policy.')
    key = rsa_decrypt_key(files['encrypted_key'])
    if len(key) != {'AES-128':16,'AES-192':24,'AES-256':32,'DES':8,'Triple-DES':24}[ALGORITHMS['encryption']]:
        raise ValueError('Invalid document key size.')
    payload = json.loads(aes_decrypt(files['encrypted'], key, iv))
    record = normalize_record(payload['record'])
    # Validate ciphertexts before expensive arithmetic, even for malicious clients.
    n = read('keys', 'paillier_public.json')['n']
    if not isinstance(files['paillier'], dict) or set(files['paillier']) != set(METRICS):
        raise ValueError('Invalid encrypted metrics.')
    for value in files['paillier'].values():
        if type(value) is not int or not 0 < value < n*n or gcd(value, n) != 1:
            raise ValueError('Invalid Paillier ciphertext.')
    files = dict(files)
    files['index'] = make_index(record, timestamp)
    files['metadata'] = dict(metadata, received_at=received)
    try:
        _pending.update({(folder, filename): value for folder, value in files.items()})
        _pending['receipts', filename] = seal(files)
        # Reuse the complete existing hash/signature/Paillier/index verification.
        check_record(record_id)
        receipt = _pending['receipts', filename]
    finally:
        _pending.clear()
    # One request at a time: no shared ROLE races or concurrent record writes.
    # Receipt is the commit marker. Startup removes interrupted, uncommitted records.
    try:
        for folder, value in files.items():
            save(folder, filename, value)
        known[ROLE] = files['public_key']
        save('keys', 'signers.json', known)
        save('receipts', filename, receipt)
        save('verified', filename, {'verified_at': received, 'receipt': receipt})
    except Exception:
        for folder in (*files, 'receipts', 'verified'):
            (BASE / folder / filename).unlink(missing_ok=True)
        raise
    return {'Record ID': record_id, 'Key unwrapping': 'PASS', 'Hash verification': 'PASS',
            'Signature verification': 'PASS', 'Timestamp validation': 'PASS',
            'Paillier consistency': 'PASS', 'Result': 'ACCEPTED'}


def public_configuration():
    names = ['paillier_public.json', 'elgamal.json', 'settings.json']
    names.append('rsa_public.json' if ALGORITHMS['key'] == 'RSA' else 'ecdh_public.json')
    if ALGORITHMS['signature'] == 'Schnorr':
        names.append('schnorr.json')
    return {name: read('keys', name) for name in names}


def dispatch(operation, arguments):
    require(operation)
    if not isinstance(arguments, dict):
        raise ValueError('Arguments must be an object.')
    if operation == 'submit_record':
        return accept_submission(arguments)
    if operation == 'search_records' and arguments:
        if set(arguments) - {'field_name','query','start','end'}:
            raise ValueError('Invalid search arguments.')
        return find_records(**arguments)
    signatures = {
        'verify_record': ('record_id',), 'view_record': ('record_id',),
        'view_text': ('record_id',), 'view_amounts': ('record_id',),
        'view_ciphertext': ('record_id',), 'view_signature': ('record_id',),
        'view_metadata': ('record_id',), 'select_records': ('record_ids',),
        'rsa_multiply': ('left','right'), 'elgamal_multiply': ('left','right'),
        'compare_demo': ('left','right')}
    if set(arguments) != set(signatures.get(operation, ())):
        raise ValueError('Wrong operation arguments.')
    if operation not in DOMAIN_ACTIONS:
        raise ValueError('Unknown operation.')
    if operation == 'aggregate_records':
        print('Paillier sum: C = product(selected ciphertexts) mod n^2')
    return globals()[operation](**arguments)


def handle_connection(connection):
    global ROLE, getpass
    original_input, original_getpass = builtins.input, getpass
    try:
        hello = receive_message(connection)
        identity = hello.get('identity')
        if not isinstance(identity, str) or identity not in ENTITIES:
            raise PermissionError('Unknown identity.')
        account = read('keys', 'accounts.json')[identity]
        nonce = secrets.token_hex(32)
        send_message(connection, {'type':'challenge', 'salt':account['salt'], 'nonce':nonce})
        proof = receive_message(connection).get('proof')
        expected = hmac.new(bytes.fromhex(account['hash']), (nonce + ':' + identity).encode(), hashlib.sha256).hexdigest()
        if not isinstance(proof, str) or not hmac.compare_digest(proof, expected):
            raise PermissionError('Access denied.')
        ROLE = identity
        send_message(connection, {'type':'authenticated'})
        request = receive_message(connection)
        operation = request.get('operation')
        if not isinstance(operation, str) or set(request) != {'operation','arguments'}:
            raise ValueError('Invalid request.')
        if operation == 'public_configuration':
            if request['arguments'] != {}:
                raise ValueError('Unexpected arguments.')
            result, output = public_configuration(), ''
        else:
            require(operation)
            buffer = io.StringIO()
            def prompt(message='', secret=False):
                output = buffer.getvalue()
                buffer.seek(0)
                buffer.truncate(0)
                send_message(connection, {'type':'prompt', 'text':message, 'secret':secret, 'output':output})
                answer = receive_message(connection).get('answer')
                if not isinstance(answer, str) or len(answer) > 8192:
                    raise ValueError('Invalid prompt answer.')
                return answer
            builtins.input = lambda message='': prompt(message)
            getpass = lambda message='': prompt(message, True)
            with contextlib.redirect_stdout(buffer):
                result = dispatch(operation, request['arguments'])
            output = buffer.getvalue()
        send_message(connection, {'type':'result', 'ok':True, 'result':result, 'output':output})
    except (OSError, ValueError, TypeError, KeyError, IndexError, OverflowError, PermissionError, InvalidOperation, RecursionError) as error:
        try:
            send_message(connection, {'type':'result','ok':False,'error':str(error) or type(error).__name__})
        except (OSError, ValueError):
            pass
    finally:
        ROLE = None
        EVENTS.clear()
        builtins.input, getpass = original_input, original_getpass


def view_ciphertext(record_id):
    require('view_ciphertext')
    record_access(record_id)
    result = {'Record ID': record_id, 'Ciphertext hex':read('encrypted', record_filename(record_id))}
    show_summary('Ciphertext', result)
    return result


def serve():
    setup()
    # Refuse incompatible reuse of a storage directory after regeneration.
    fingerprint = hashlib.sha256(json.dumps([DOMAIN, ENTITIES, ALGORITHMS], sort_keys=True).encode()).hexdigest()
    config_path = BASE / 'keys' / 'network_config.json'
    if config_path.exists() and read('keys','network_config.json') != fingerprint:
        raise ValueError('Configuration changed; use a new output/storage folder.')
    save('keys','network_config.json',fingerprint)
    for folder in FOLDERS:
        if folder in ('keys','authorities','tally','receipts'):
            continue
        for file in (BASE / folder).glob('*.json'):
            if not (BASE / 'receipts' / file.name).exists():
                file.unlink()
    host = os.environ.get('CRYPTO_HOST', NETWORK['host'])
    port = int(os.environ.get('CRYPTO_PORT', NETWORK['port']))
    context = None
    cert, key = os.environ.get('CRYPTO_TLS_CERT'), os.environ.get('CRYPTO_TLS_KEY')
    if cert and key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
    if host not in ('127.0.0.1','localhost','::1') and context is None:
        raise ValueError('Remote binding requires CRYPTO_TLS_CERT and CRYPTO_TLS_KEY.')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(16)
        print(f'Listening on {host}:{port}. Ctrl+C to stop.')
        while True:
            connection, address = listener.accept()
            with connection:
                connection.settimeout(120)
                try:
                    if context:
                        with context.wrap_socket(connection, server_side=True) as secure:
                            handle_connection(secure)
                    else:
                        handle_connection(connection)
                except (OSError, ValueError):
                    continue


if __name__ == '__main__':
    try:
        serve()
    except (KeyboardInterrupt, EOFError):
        print('Server stopped.')
    except (OSError, ValueError) as error:
        print('Server error:', error)
