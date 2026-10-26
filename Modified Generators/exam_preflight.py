"""Debian/PyCharm preflight. Run BEFORE the exam while internet is available.
Default: check/repair PyCryptodome and phe. --with-concrete adds Concrete FHE.
--check-only never installs. --scan FILE [FILE ...] checks code, including templates.
No sudo, virtual environment creation, system-policy bypass, or arbitrary packages.
"""
import sys
if sys.version_info < (3, 9):
    print('FAIL: Python 3.9+ required. Selected interpreter:', sys.executable)
    sys.exit(1)
import argparse
import ast
import importlib.metadata
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

STANDARD = '''ast base64 builtins contextlib datetime decimal getpass hashlib hmac io json math os pathlib pickle random re secrets socket ssl struct sys tempfile time types unittest unittest.mock argparse importlib importlib.metadata subprocess shlex'''.split()

PROBES = {}
PROBES['standard'] = r'''
import importlib
for name in STANDARD:
    importlib.import_module(name)
from math import gcd, lcm
from secrets import randbelow
from time import perf_counter
from unittest import mock
assert gcd(12,18)==6 and lcm(12,18)==36 and 0 <= randbelow(10) < 10
import hashlib, hmac, socket, ssl, struct, json, tempfile
assert len(hashlib.sha512(b'test').digest()) == 64
assert len(hashlib.scrypt(b'test', salt=b'0123456789abcdef', n=16384,r=8,p=1,dklen=32))==32
assert hmac.compare_digest('abc','abc')
ssl.create_default_context()
with tempfile.TemporaryDirectory() as d:
    from pathlib import Path
    p=Path(d)/'test.json';p.write_text(json.dumps({'ok':True}));assert json.loads(p.read_text())['ok']
with socket.socket() as listener:
    listener.bind(('127.0.0.1',0));listener.listen(1)
    with socket.create_connection(listener.getsockname(),timeout=5) as client:
        server,_=listener.accept()
        with server:
            server.settimeout(5);client.sendall(struct.pack('!I',2)+b'OK')
            data=b''
            while len(data)<6:data+=server.recv(6-len(data))
            assert data==struct.pack('!I',2)+b'OK'
print('PASS standard-library imports, scrypt, SHA512, files, SSL context, localhost TCP')
'''
PROBES['pycryptodome'] = r'''
from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA, ElGamal, ECC, DSA
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, inverse
from Crypto.Protocol.DH import key_agreement
from Crypto.Signature import pkcs1_15
import Crypto, os, secrets, math
print('Crypto location:',Crypto.__file__)
assert inverse(3,11)==4
for module,size in [(AES,16),(AES,24),(AES,32),(DES,8),(DES3,24)]:
    key=os.urandom(size)
    if module is DES3:key=DES3.adjust_key_parity(key)
    modes=['CBC','ECB','CTR','EAX']+(['GCM'] if module is AES else [])
    for mode in modes:
        n={'CBC':module.block_size,'ECB':0,'CTR':module.block_size//2,'EAX':module.block_size,'GCM':12}[mode]
        parameter=os.urandom(n)
        kwargs={} if mode=='ECB' else {'iv' if mode=='CBC' else 'nonce':parameter}
        enc=module.new(key,getattr(module,'MODE_'+mode),**kwargs)
        dec=module.new(key,getattr(module,'MODE_'+mode),**kwargs)
        data='test ಕನ್ನಡ'.encode()
        if mode in ['CBC','ECB']:
            assert unpad(dec.decrypt(enc.encrypt(pad(data,module.block_size))),module.block_size)==data
        elif mode in ['EAX','GCM']:
            ct,tag=enc.encrypt_and_digest(data);assert dec.decrypt_and_verify(ct,tag)==data
        else:assert dec.decrypt(enc.encrypt(data))==data
print('PASS all 23 AES/DES/TripleDES cipher-mode combinations')
key=RSA.generate(4096);session=os.urandom(32)
wrapped=PKCS1_OAEP.new(key.public_key(),hashAlgo=SHA256).encrypt(session)
assert PKCS1_OAEP.new(key,hashAlgo=SHA256).decrypt(wrapped)==session
sig=pkcs1_15.new(key).sign(SHA256.new(b'test'))
pkcs1_15.new(key.public_key()).verify(SHA256.new(b'test'),sig)
a=ECC.generate(curve='P-256');b=ECC.generate(curve='P-256')
kdf=lambda x:SHA256.new(x).digest()
assert key_agreement(static_priv=a,static_pub=b.public_key(),kdf=kdf)==key_agreement(static_priv=b,static_pub=a.public_key(),kdf=kdf)
group=DSA.generate(2048)
p,q,g=int(group.p),int(group.q),int(group.g)
x=secrets.randbelow(q-1)+1;y=pow(g,x,p);nonce=secrets.randbelow(q-1)+1
commitment=pow(g,nonce,p);challenge=123;response=(nonce+x*challenge)%q
assert pow(g,response,p)*pow(pow(y,challenge,p),-1,p)%p==commitment
elg=ElGamal.generate(512,os.urandom);p,g,x,y=map(int,(elg.p,elg.g,elg.x,elg.y))
while True:
    k=secrets.randbelow(p-2)+1
    if math.gcd(k,p-1)==1:break
r=pow(g,k,p);h=1234567;s=(h-x*r)*inverse(k,p-1)%(p-1)
assert pow(g,h,p)==pow(y,r,p)*pow(r,s,p)%p
print('PASS RSA4096 OAEP, RSA signature, ECDH, Schnorr arithmetic, ElGamal signature')
# Small disposable primes test the generator's Paillier math, not production security.
while True:
    p,q=getPrime(256),getPrime(256);n=p*q;lam=math.lcm(p-1,q-1)
    if p!=q and math.gcd(lam,n)==1:break
def enc(m):
    while True:
        r=secrets.randbelow(n-1)+1
        if math.gcd(r,n)==1:return pow(n+1,m,n*n)*pow(r,n,n*n)%(n*n)
c=enc(5)*enc(10)%(n*n);d=lam*inverse(lam,n);period=n*lam
share1=secrets.randbelow(period-1)+1;share2=(d-share1)%period
combined=pow(c,share1,n*n)*pow(c,share2,n*n)%(n*n)
assert ((combined-1)//n)%n==15
print('PASS custom Paillier encrypted sum and two-share arithmetic')
'''
PROBES['phe'] = r'''
from phe import paillier
import phe
print('phe location:',phe.__file__)
pub,priv=paillier.generate_paillier_keypair(n_length=512)
assert priv.decrypt(pub.encrypt(5)+pub.encrypt(10))==15
assert priv.decrypt(pub.encrypt(5)*10)==50
print('PASS phe Paillier encrypted addition/scalar multiplication (disposable test keys)')
'''
PROBES['concrete-python'] = r'''
from concrete import fhe
import concrete
print('concrete location:',getattr(concrete,'__file__',None))
def add(x,y):return x+y
compiler=fhe.Compiler(add, {'x':'encrypted','y':'encrypted'})
circuit=compiler.compile([(x,y) for x in range(4) for y in range(4)])
assert circuit.encrypt_run_decrypt(2,3)==5
print('PASS Concrete compile, key generation, encryption, evaluation and decryption')
'''

def scan_files(paths):
    imports=set();issues=[]
    def inspect(source,depth=0):
        tree=ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):imports.update(a.name.split('.')[0] for a in node.names)
            elif isinstance(node,ast.ImportFrom) and node.level==0 and node.module:imports.add(node.module.split('.')[0])
            elif depth<2 and isinstance(node,ast.Constant) and isinstance(node.value,str) and 'import ' in node.value:
                try:inspect(node.value,depth+1)
                except (SyntaxError,ValueError):pass
    for path in paths:
        try:inspect(path.read_text(encoding='utf-8-sig'))
        except Exception as e:issues.append(str(path)+': '+str(e))
    return imports,issues


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only',action='store_true')
    parser.add_argument('--with-concrete',action='store_true',help='Also install/check Zama Concrete FHE; can be slow/heavy.')
    parser.add_argument('--scan',nargs='+',type=Path,help='Explicit Python/code-text files to inspect, without executing them.')
    parser.add_argument('--timeout',type=int,default=300,help='Seconds allowed per ordinary probe; Concrete gets at least 600.')
    args=parser.parse_args()
    base=Path(__file__).resolve().parent
    lines=[]
    def log(message):
        print(message,flush=True);lines.append(message)
    def run(command,timeout):
        try:
            p=subprocess.run(command,cwd=os.getcwd(),capture_output=True,text=True,errors='replace',timeout=timeout)
            return p.returncode,(p.stdout+p.stderr).strip()
        except subprocess.TimeoutExpired as e:
            return 124,'Timed out after '+str(timeout)+' seconds. This is NOT a pass.'
        except OSError as e:return 1,str(e)
    def probe(name):
        log('Checking '+name+' ...')
        rc,out=run([sys.executable,'-c','STANDARD='+repr(STANDARD)+'\n'+PROBES[name]],max(args.timeout,600) if name=='concrete-python' else args.timeout)
        log(out or '(no output)');return rc==0
    log('Python: '+sys.version.replace('\n',' '))
    log('Interpreter: '+sys.executable)
    log('Working directory: '+os.getcwd())
    log('Mode: '+('CHECK ONLY - no installation' if args.check_only else 'CHECK AND INSTALL/REPAIR missing or failing external packages'))
    paths=args.scan if args.scan is not None else [p for name in ['generator.py','client.py','server.py'] for p in [base/name] if p.exists()]
    imports,issues=scan_files(paths)
    log('Scanned files: '+(', '.join(map(str,paths)) or 'none; built-in checklist still covers your supplied imports'))
    log('Detected imports (including embedded code): '+', '.join(sorted(imports)))
    for issue in issues:log('SCAN ERROR: '+issue)
    known=set(getattr(sys,'stdlib_module_names',()))|{m.split('.')[0] for m in STANDARD}|{'Crypto','phe','concrete'}
    unknown=imports-known
    if unknown:log('UNRESOLVED imports (not auto-installed): '+', '.join(sorted(unknown)))
    selected=['pycryptodome','phe']
    if args.with_concrete or 'concrete' in imports:selected.append('concrete-python')
    else:log('Concrete FHE NOT CHECKED/INSTALLED; use --with-concrete if your exam code imports concrete.fhe.')
    outcomes={'standard':probe('standard')}
    pip_ready=None
    for package in selected:
        ok=probe(package)
        if not ok and not args.check_only:
            if pip_ready is None:
                rc,out=run([sys.executable,'-m','pip','--version'],60)
                if rc:
                    log('pip missing: trying Python ensurepip (Debian may disable it).')
                    rc,out=run([sys.executable,'-m','ensurepip','--user'],120)
                    log(out)
                    rc,out=run([sys.executable,'-m','pip','--version'],60)
                pip_ready=rc==0;log(out)
            if pip_ready:
                # A fixed allowlist: never guess a pip project from arbitrary import names.
                command=[sys.executable,'-m','pip','install','--disable-pip-version-check','--no-input','--timeout','25','--retries','1','--upgrade',package]
                log('Installing: '+shlex.join(command))
                rc,out=run(command,1200);log(out)
                if rc:log('INSTALL FAILED: check internet, permissions, Python/wheel compatibility, disk space and Debian package policy.')
                ok=probe(package)  # fresh interpreter; success requires actual working functionality
            else:log('Cannot install: pip unavailable. Ask the lab administrator to provide pip/dependencies for this interpreter.')
        outcomes[package]=ok
    rc,out=run([sys.executable,'-m','pip','check'],90)
    log('pip dependency consistency: '+out)
    dependency_ok=rc==0
    log('\nRESULTS')
    for name,ok in outcomes.items():log(('PASS ' if ok else 'FAIL ')+name)
    generator_ready=outcomes['standard'] and outcomes['pycryptodome']
    log('GENERATOR DEPENDENCY CHECK: '+('PASS' if generator_ready else 'FAIL'))
    all_ok=all(outcomes.values()) and dependency_ok and not unknown and not issues
    log('ALL SELECTED CHECKS: '+('PASS' if all_ok else 'FAIL / NEEDS ATTENTION'))
    log('This verifies the selected interpreter and smoke tests, not every future program/input or another lab machine.')
    log('Do NOT install the unrelated package concrete for Zama FHE. Use concrete-python.')
    log('Debian externally-managed-environment: ask staff for an approved setup; this script never uses sudo or --break-system-packages.')
    log('Local files named Crypto.py, concrete.py, phe.py, socket.py, math.py etc. can shadow installed modules. Move/rename only your conflicting project file.')
    log('Debian Cryptodome imports do not satisfy these scripts\' Crypto imports. Check the interpreter/namespace, not only the Debian package name.')
    log('Before exam: rerun with --check-only, in the SAME PyCharm interpreter, preferably with internet disconnected.')
    log('Also run your actual generator and client/server with test records. Library checks alone cannot guarantee an error-free exam.')
    versions=[]
    for name in selected:
        if outcomes[name]:
            try:versions.append(name+'=='+importlib.metadata.version(name))
            except importlib.metadata.PackageNotFoundError:pass
    try:
        (base/'preflight_report.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
        (base/'requirements_verified.txt').write_text('# Only packages which passed; NOT a complete dependency lock.\n'+'\n'.join(versions)+'\n',encoding='utf-8')
        rc,frozen=run([sys.executable,'-m','pip','freeze'],60)
        if rc==0:(base/'environment_snapshot.txt').write_text('# Entire interpreter snapshot, including unrelated packages; not automatically portable.\n'+frozen+'\n',encoding='utf-8')
        print('Saved preflight_report.txt and requirements_verified.txt beside this script.')
    except OSError as e:print('Could not save report:',e)
    return 0 if all_ok else 1

if __name__=='__main__':
    try:sys.exit(main())
    except KeyboardInterrupt:
        print('\nInterrupted. Incomplete checks are not a pass.');sys.exit(130)
