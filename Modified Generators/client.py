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

BASE = Path(__file__).resolve().parent / "record_files"

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

ALGORITHMS = {'encryption': 'AES-256', 'hash': 'SHA-512', 'key': 'RSA', 'signature': 'ElGamal', 'search': 'SSE', 'rsa_bits': {'key': 4096, 'signature': 2048, 'search': 2048}, 'cipher': {'mode': 'CBC', 'padding': 'PKCS7', 'iv_source': 'random', 'iv_hex': ''}, 'show_paillier_on_submit': True}

DOMAIN = {'title': 'Secure Electronic Voting', 'record_name': 'Ballot', 'fields': [{'name': 'CandidateID', 'type': 'choice', 'search': False, 'sum': False, 'count': True, 'choices': ['1', '2', '3']}, {'name': 'ConstituencyID', 'type': 'text', 'search': True, 'sum': False, 'count': False}], 'use_deadline': True, 'close_on_aggregate': True, 'min_records': 2}

ENTITIES = {'Voter': ['submit_record', 'view_own_records', 'view_own_signatures'], 'Election Server': ['verify_record', 'search_records', 'view_all_records', 'view_signature', 'view_metadata'], 'Tally Authority': ['aggregate_records', 'threshold_decrypt', 'select_records', 'view_aggregate_ciphertext']}

DOMAIN_ACTIONS = {'submit_record': 'Submit record: hash, sign, encrypt, protect key, encrypt totals and index', 'verify_record': 'Verify record: decrypt internally, compare hashes/signature and validate metadata', 'view_record': 'View full record details (all submissions; plaintext fields)', 'search_records': 'Search text by words, other fields by exact value, or submission time', 'aggregate_records': 'Aggregate selected verified records (Paillier addition)', 'threshold_decrypt': 'Decrypt aggregate using both authority passwords', 'view_all_records': 'List all submitted records (permitted fields)', 'view_own_records': 'View all submitted by me (including contents)', 'view_own_signatures': 'View all digital signatures by me', 'view_text': 'View plaintext text/description and category fields', 'view_amounts': 'View individual numeric/amount fields', 'view_ciphertext': 'View ciphertext (key shown only to its submitter)', 'view_signature': 'View an existing digital signature', 'select_records': 'Select record IDs for aggregation', 'verify_selected': 'Verify selected records', 'rsa_multiply': 'RSA homomorphic multiplication (no OAEP padding)', 'elgamal_multiply': 'ElGamal homomorphic multiplication', 'compare_demo': 'Compare numbers after ElGamal decryption', 'view_aggregate_ciphertext': 'View saved Paillier aggregate ciphertext (no decryption)', 'view_metadata': 'View record metadata only (no plaintext fields)'}

METRICS = {'record_count': {'kind': 'record_count', 'label': 'Record count', 'scale': 1, 'decimals': 0}, 'count_0_0': {'kind': 'count', 'label': 'CandidateID = 1', 'field': 'CandidateID', 'choice': '1', 'scale': 1, 'decimals': 0}, 'count_0_1': {'kind': 'count', 'label': 'CandidateID = 2', 'field': 'CandidateID', 'choice': '2', 'scale': 1, 'decimals': 0}, 'count_0_2': {'kind': 'count', 'label': 'CandidateID = 3', 'field': 'CandidateID', 'choice': '3', 'scale': 1, 'decimals': 0}, 'choice_sum_CandidateID': {'kind': 'sum', 'label': 'Total CandidateID', 'field': 'CandidateID', 'scale': 1, 'decimals': 0}}

def now():
    return datetime.now(IST).strftime(TIME_FORMAT)

def password_key(password, salt):
    return hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=32,
    )

def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)

    ciphertext = cipher.encrypt(
        pad(plaintext.encode(), AES.block_size)
    )

    return cipher.iv.hex(), ciphertext.hex()

def rsa_encrypt_key(key):
    public_key = RSA.import_key(
        read("keys", "rsa_public.json")
    )

    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)

    return cipher.encrypt(key).hex()

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

from Crypto.Cipher import DES, DES3

from Crypto.PublicKey import ECC, DSA

from Crypto.Protocol.DH import key_agreement

from Crypto.Signature import pkcs1_15

_original_generate_signing_keys = generate_signing_keys

_original_sign_hash = sign_hash

_original_signature_values = signature_values

_original_encrypt_key = rsa_encrypt_key

_original_search_token = search_token

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

def entity_menu(entity):
    if ROLE != entity or entity not in ENTITIES:
        raise PermissionError('Wrong entity session.')
    names = [action for action in DOMAIN_ACTIONS if action in ENTITIES[entity] and action != 'access_all_records']
    while True:
        print('\n' + entity)
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
PUBLIC = {}
PASSWORD = None


def read(folder, filename):
    if folder != 'keys' or filename not in PUBLIC:
        raise PermissionError('The client has no access to server-private files.')
    return PUBLIC[filename]


def rpc(operation, arguments=None, prompt_handler=None):
    host = os.environ.get('CRYPTO_HOST', NETWORK['host'])
    port = int(os.environ.get('CRYPTO_PORT', NETWORK['port']))
    cafile = os.environ.get('CRYPTO_TLS_CA')
    if host not in ('127.0.0.1','localhost','::1') and not cafile:
        raise ValueError('Remote connections require CRYPTO_TLS_CA (trusted server certificate/CA).')
    with socket.create_connection((host, port), timeout=10) as raw:
        context = ssl.create_default_context(cafile=cafile) if cafile else None
        connection = context.wrap_socket(raw, server_hostname=host) if context else raw
        try:
            connection.settimeout(120)
            send_message(connection, {'identity':ROLE})
            challenge = receive_message(connection)
            if challenge.get('type') != 'challenge':
                raise PermissionError(challenge.get('error','Invalid server challenge.'))
            derived = password_key(PASSWORD, bytes.fromhex(challenge['salt']))
            proof = hmac.new(derived, (challenge['nonce'] + ':' + ROLE).encode(), hashlib.sha256).hexdigest()
            send_message(connection, {'proof':proof})
            authenticated = receive_message(connection)
            if authenticated.get('type') != 'authenticated':
                raise PermissionError(authenticated.get('error','Authentication failed.'))
            send_message(connection, {'operation':operation, 'arguments':arguments or {}})
            while True:
                response = receive_message(connection)
                if response.get('type') == 'prompt':
                    if response.get('output'):
                        print(response['output'], end='')
                    answer = (prompt_handler(response) if prompt_handler else
                              (getpass(response['text']) if response['secret'] else input(response['text'])))
                    send_message(connection, {'answer':answer})
                    continue
                if response.get('type') != 'result' or type(response.get('ok')) is not bool:
                    raise ValueError('Invalid server response.')
                if not response['ok']:
                    raise ValueError(response.get('error','Server rejected request.'))
                if response.get('output'):
                    print(response['output'], end='')
                return response.get('result')
        finally:
            if connection is not raw:
                connection.close()


def signing_identity():
    # One encrypted local signing key per configured account and server key set.
    folder = Path(__file__).resolve().parent / 'client_keys'
    folder.mkdir(exist_ok=True)
    fingerprint = hashlib.sha256(json.dumps([ROLE, PUBLIC, ALGORITHMS], sort_keys=True).encode()).hexdigest()
    path = folder / (fingerprint + '.json')
    if path.exists():
        item = json.loads(path.read_text(encoding='utf-8'))
        key = password_key(PASSWORD, bytes.fromhex(item['salt']))
        cipher = AES.new(key, AES.MODE_EAX, nonce=bytes.fromhex(item['nonce']))
        pair = json.loads(cipher.decrypt_and_verify(bytes.fromhex(item['ciphertext']), bytes.fromhex(item['tag'])))
        return pair['private'], pair['public']
    private, public = generate_signing_keys()
    if isinstance(private, bytes):
        private = private.decode()
    salt = os.urandom(16)
    cipher = AES.new(password_key(PASSWORD, salt), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps({'private':private,'public':public}).encode())
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps({'salt':salt.hex(),'nonce':cipher.nonce.hex(),'ciphertext':ciphertext.hex(),'tag':tag.hex()}), encoding='utf-8')
    os.replace(temporary, path)
    return private, public


def prepare_submission(record_id, values, timestamp=None):
    record_filename(record_id)
    record = normalize_record(values)
    timestamp = timestamp or now()
    digest = hash_message(signed_record(record_id, record, ROLE, timestamp))
    private, public = signing_identity()
    signature = sign_hash(digest, private, public)
    n = PUBLIC['paillier_public.json']['n']
    encrypted, randomness = {}, {}
    for name, value in metric_values(record).items():
        encrypted[name], randomness[name] = paillier_encrypt(value, n)
    payload = json.dumps({'record':record,'randomness':randomness}, ensure_ascii=False)
    key = document_key()
    iv, ciphertext = aes_encrypt(payload, key, **configured_cipher_options())
    wrapped = rsa_encrypt_key(key)
    return {'record_id':record_id, 'files':{
        'encrypted':ciphertext, 'encrypted_key':wrapped, 'iv':iv, 'hashes':digest,
        'signature':signature,'public_key':public,'paillier':encrypted,
        'metadata':{'version':3,'submitted_at':timestamp,'submitted_by':ROLE,
                    'signed_by':ROLE,'signature_algorithm':ALGORITHMS['signature']}}}


def submit_record(record_id, values):
    require('submit_record')
    bundle = prepare_submission(record_id, values)
    files = bundle['files']
    print(ALGORITHMS['hash'] + ':', files['hashes'])
    print('Signature:', files['signature'])
    print('IV/nonce:', files['iv']['parameter'])
    print('Ciphertext:', files['encrypted'])
    wrapped = str(files['encrypted_key'])
    print('Wrapped key:', wrapped[:80] + ('...' if len(wrapped) > 80 else ''))
    if ALGORITHMS['show_paillier_on_submit']:
        print('Paillier ciphertexts:', files['paillier'])
    print('Timestamp (IST):', files['metadata']['submitted_at'])
    result = rpc('submit_record', bundle)
    for label, value in result.items():
        print(label + ':', value)
    return result


def remote_operation(action):
    names = {
        'verify_record':('record_id',), 'view_record':('record_id',),
        'view_text':('record_id',), 'view_amounts':('record_id',),
        'view_ciphertext':('record_id',), 'view_signature':('record_id',),
        'view_metadata':('record_id',), 'select_records':('record_ids',),
        'rsa_multiply':('left','right'), 'elgamal_multiply':('left','right'),
        'compare_demo':('left','right')}
    def invoke(*args):
        return rpc(action, dict(zip(names.get(action, ()), args)))
    return invoke


for _action in DOMAIN_ACTIONS:
    if _action != 'submit_record':
        globals()[_action] = remote_operation(_action)


def client_main():
    global ROLE, PASSWORD, PUBLIC
    names = list(ENTITIES)
    while True:
        for number, identity in enumerate(names, 1):
            print(f'{number}. {identity}')
        print('0. Exit')
        choice = input('Identity: ').strip()
        if choice == '0':
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(names):
            print('Invalid choice.')
            continue
        ROLE = names[int(choice)-1]
        PASSWORD = getpass('Password: ')
        try:
            PUBLIC = rpc('public_configuration')
            entity_menu(ROLE)
        except (OSError, ValueError, TypeError, KeyError, PermissionError) as error:
            print('Connection or operation failed:', error)
        finally:
            ROLE, PASSWORD, PUBLIC = None, None, {}


if __name__ == '__main__':
    try:
        client_main()
    except (KeyboardInterrupt, EOFError):
        print('Client closed.')
