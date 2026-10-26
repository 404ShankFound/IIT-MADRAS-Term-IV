"""Offline homomorphic lab calculator. Python 3.8+, standard library only.

Run: python he_calculator.py

Modes: Paillier addition; textbook RSA / raw ElGamal multiplication;
EXPERIMENTAL, INSECURE bounded-depth encrypted Boolean circuits.
The circuit mode is NOT FHE: it has no bootstrapping and refuses operations
when a conservative noise/resource limit would be exceeded. It is for small
educational examples only. No production security is claimed for this file.

All registers are session-local ciphertexts; no input plaintext is stored.
Only the explicit Reveal command decrypts. One local process owns the key:
this is not authentication, distributed key custody, or threshold decryption.

Generic workflow: enter named inputs, operate on their names, save each
result under a new name, use those names in subsequent operations, reveal
only the desired final value. No application-specific menus or fixed rates.
Circuit integers are unsigned; add/multiply grow the output width. Subtract
wraps modulo 2**width (shown on screen). Comparison returns an encrypted bit.
Division is unsupported. For percentages, compute amount*(100+rate), reveal
the result, and use the Reveal display divisor 100 (integer/fraction output).
Candidate vote counts require separate indicator sums, not sums of IDs.
"""

import math
import secrets
import time
from functools import reduce
from fractions import Fraction


def integer(prompt, lo=None, hi=None):
    while True:
        try:
            n = int(input(prompt))
            if (lo is not None and n < lo) or (hi is not None and n > hi):
                raise ValueError()
            return n
        except ValueError:
            print('Enter an integer in range:', lo, 'to', hi)


def probable_prime(n, rounds=32):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def prime(bits):
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if probable_prime(p):
            return p


class PHE:
    def __init__(self, mode, bits):
        self.mode = mode
        if mode == 'elgamal':
            # Safe-prime full multiplicative group, raw integer encoding.
            while True:
                q = prime(bits - 1)
                p = 2 * q + 1
                if probable_prime(p):
                    break
            while True:
                g = secrets.randbelow(p - 3) + 2
                if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
                    break
            self.modulus, self.g = p, g
            self.secret = secrets.randbelow(p - 2) + 1
            self.y = pow(g, self.secret, p)
            return
        while True:
            p, q = prime(bits // 2), prime(bits - bits // 2)
            if p == q:
                continue
            n = p * q
            lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
            if math.gcd(lam, n) == 1 and math.gcd(65537, lam) == 1:
                break
        self.modulus = n
        self.lam = lam
        self.mu = pow(lam, -1, n)
        self.e, self.d = 65537, pow(65537, -1, lam)

    def encrypt(self, m):
        n = self.modulus
        if not (0 <= m < n) or (self.mode == 'elgamal' and m == 0):
            raise ValueError('Input outside plaintext group/range.')
        if self.mode == 'rsa':
            return pow(m, self.e, n)
        if self.mode == 'elgamal':
            r = secrets.randbelow(n - 2) + 1
            return pow(self.g, r, n), m * pow(self.y, r, n) % n
        while True:
            r = secrets.randbelow(n - 1) + 1
            if math.gcd(r, n) == 1:
                break
        return pow(n + 1, m, n*n) * pow(r, n, n*n) % (n*n)

    def decrypt(self, c):
        n = self.modulus
        if self.mode == 'rsa':
            return pow(c, self.d, n)
        if self.mode == 'elgamal':
            a, b = c
            return b * pow(pow(a, self.secret, n), -1, n) % n
        return ((pow(c, self.lam, n*n) - 1) // n) * self.mu % n

    def combine(self, a, b):
        n = self.modulus
        if self.mode == 'elgamal':
            return a[0]*b[0] % n, a[1]*b[1] % n
        return a*b % (n*n if self.mode == 'paillier' else n)


# Toy symmetric noisy integer encryption:
# c = p*q + 2*r + bit; decrypt = (c % p) % 2.
# XOR is ciphertext addition; AND is ciphertext multiplication.
# No modular reduction or secret-key operation occurs in evaluation.
# Each ciphertext also carries a PUBLIC conservative noise exponent k:
# its nonnegative residual is < 2**k. Refuse before it can reach p.
# Small randomness and unaudited parameters make this deliberately insecure.
class Bits:
    ZERO = (0, 0)
    ONE = (1, 1)

    def __init__(self, key_bits):
        self.p = secrets.randbits(key_bits) | (1 << (key_bits-1)) | 1
        self.limit = key_bits - 1

    def gate(self, a, b, multiply=False):
        if multiply and (a == self.ZERO or b == self.ZERO):
            return self.ZERO
        if multiply and a == self.ONE:
            return b
        if multiply and b == self.ONE:
            return a
        if not multiply and a == self.ZERO:
            return b
        if not multiply and b == self.ZERO:
            return a
        k = a[1] + b[1] if multiply else max(a[1], b[1]) + 1
        estimated = (a[0].bit_length() + b[0].bit_length()
                     if multiply else max(a[0].bit_length(), b[0].bit_length()) + 1)
        if k > self.limit or estimated > 2000000:
            raise ValueError('Toy circuit depth/size limit reached. No decryption or refresh performed.')
        return (a[0]*b[0] if multiply else a[0]+b[0], k)

    def xor(self, a, b):
        return self.gate(a, b)

    def AND(self, a, b):
        return self.gate(a, b, True)

    def NOT(self, a):
        return self.xor(a, self.ONE)

    def encrypt(self, value, width):
        if not 0 <= value < 2**width:
            raise ValueError('Value does not fit the chosen unsigned width.')
        return tuple((self.p * (secrets.randbits(32) + 1)
                      + 2*secrets.randbelow(256) + ((value >> i) & 1), 9)
                     for i in range(width))

    def decrypt(self, word):
        return sum(((c % self.p) % 2) << i for i, (c, _) in enumerate(word))

    def pad(self, word, width):
        return tuple(word) + (self.ZERO,) * (width-len(word))

    def add(self, a, b, width=None, carry=None):
        width = width or max(len(a), len(b)) + 1
        a, b = self.pad(a, width), self.pad(b, width)
        carry = self.ZERO if carry is None else carry
        out = []
        for i in range(width):
            t = self.xor(a[i], b[i])
            out.append(self.xor(t, carry))
            # ab and carry*(a XOR b) are disjoint Boolean conditions.
            carry = self.xor(self.AND(a[i], b[i]), self.AND(carry, t))
        return tuple(out)

    def sub(self, a, b):
        width = max(len(a), len(b))
        b = tuple(self.NOT(x) for x in self.pad(b, width))
        return self.add(a, b, width, self.ONE)

    def mul(self, a, b):
        width = len(a) + len(b)
        out = (self.ZERO,) * width
        for i, bit in enumerate(b):
            row = (self.ZERO,) * i + tuple(self.AND(x, bit) for x in a)
            out = self.add(out, self.pad(row, width), width)
        return out

    def compare(self, a, b, op):
        width = max(len(a), len(b))
        a, b = self.pad(a, width), self.pad(b, width)
        eq, gt = self.ONE, self.ZERO
        for i in reversed(range(width)):
            term = self.AND(eq, self.AND(a[i], self.NOT(b[i])))
            gt = self.xor(gt, term)
            eq = self.AND(eq, self.NOT(self.xor(a[i], b[i])))
        ge = self.xor(gt, eq)
        result = {'>': gt, '>=': ge, '==': eq,
                  '!=': self.NOT(eq), '<': self.NOT(ge), '<=': self.NOT(gt)}
        return (result[op],)

    def select(self, condition, yes, no):
        if len(condition) != 1:
            raise ValueError('Condition must be a comparison result (one encrypted bit).')
        width = max(len(yes), len(no))
        yes, no = self.pad(yes, width), self.pad(no, width)
        c = condition[0]
        return tuple(self.xor(n, self.AND(c, self.xor(y, n)))
                     for y, n in zip(yes, no))


def short(value):
    # Hex avoids Python's large-decimal-string limit.
    if isinstance(value, tuple):
        return '[' + ', '.join(short(v) for v in value[:3]) + (' ...' if len(value)>3 else '') + ']'
    h = hex(value)
    return h if len(h) < 70 else h[:30] + '...' + h[-20:] + ' (%s bits)' % value.bit_length()


def session(engine):
    registers = {}
    toy = isinstance(engine, Bits)
    def pick(prompt='Name: '):
        return registers[input(prompt).strip()]
    def save(value):
        name = input('New result name: ').strip()
        if not name or name in registers:
            raise ValueError('Use a new, nonempty name; existing results are preserved.')
        registers[name] = value
        print('Saved encrypted result:', name)
    def operation(op, a, b):
        if toy:
            return {'sum': engine.add, 'product': engine.mul}[op](a, b)
        expected = 'sum' if engine.mode == 'paillier' else 'product'
        if op != expected:
            raise ValueError('This PHE mode supports ' + expected + ' only.')
        return engine.combine(a, b)
    while True:
        print('\n1 Enter/encrypt  2 List ciphertexts  3 Sum  4 Product')
        print('5 Sum of pairwise products  6 Compare  7 Conditional select')
        print('8 Public scalar multiply  9 Subtract  10 Reveal result')
        print('11 Time a sum/product  0 End session')
        choice = input('Choose: ').strip()
        if choice == '0':
            return
        try:
            if choice == '1':
                if toy:
                    width = integer('Input width, bits (1..16; start with 4): ', 1, 16)
                    value = engine.encrypt(integer('Unsigned input: ', 0, 2**width-1), width)
                else:
                    value = engine.encrypt(integer('Input integer: ', 1 if engine.mode=='elgamal' else 0, engine.modulus-1))
                save(value)
            elif choice == '2':
                for name, c in registers.items():
                    print(name, short(c), 'width='+str(len(c)) if toy else '')
                if not registers:
                    print('No values entered.')
            elif choice in ('3', '4', '11'):
                op = 'sum' if choice == '3' else 'product'
                if choice == '11':
                    op = input('Operation (sum/product): ').strip()
                    if op not in ('sum', 'product'):
                        raise ValueError('Choose sum or product.')
                names = input('Names separated by spaces: ').split()
                if not names:
                    raise ValueError('Enter at least one name.')
                items = [registers[n] for n in names]
                repetitions = integer('Timing repetitions: ', 1, 100) if choice=='11' else 1
                start = time.perf_counter()
                for _ in range(repetitions):
                    result = reduce(lambda a,b: operation(op,a,b), items)
                print('Mean evaluation seconds:', (time.perf_counter()-start)/repetitions)
                save(result)
            elif choice == '5':
                if not toy:
                    raise ValueError('Both encrypted sum and product require the toy circuit mode here.')
                count = integer('How many pairs? ', 1)
                terms = [engine.mul(pick('Left name: '), pick('Right name: ')) for _ in range(count)]
                save(reduce(engine.add, terms))
            elif choice == '6':
                if not toy:
                    raise ValueError('PHE alone does not provide this comparison.')
                a, b = pick('First name: '), pick('Second/threshold name: ')
                op = input('Operator: > >= < <= == != : ').strip()
                if op not in ('>', '>=', '<', '<=', '==', '!='):
                    raise ValueError('Invalid comparison.')
                save(engine.compare(a,b,op))
            elif choice == '7':
                if not toy:
                    raise ValueError('Use the toy circuit mode for encrypted selection.')
                save(engine.select(pick('Condition name: '), pick('If true name: '), pick('If false name: ')))
            elif choice == '8':
                a = pick()
                k = integer('Public nonnegative multiplier: ', 0)
                if toy:
                    public_bits = tuple(engine.ONE if (k>>i)&1 else engine.ZERO for i in range(max(1,k.bit_length())))
                    save(engine.mul(a, public_bits))
                elif engine.mode == 'paillier':
                    save(pow(a,k,engine.modulus**2))
                else:
                    save(engine.combine(a, engine.encrypt(k)))
            elif choice == '9':
                a,b = pick('First name: '), pick('Second name: ')
                if toy:
                    print('Unsigned subtraction wraps modulo 2**', max(len(a),len(b)))
                    save(engine.sub(a,b))
                elif engine.mode == 'paillier':
                    n2 = engine.modulus**2
                    save(a*pow(b,-1,n2)%n2)
                else:
                    raise ValueError('Subtraction is unsupported in this PHE mode.')
            elif choice == '10':
                c = pick('Result to reveal: ')
                divisor = integer('Display divisor (1 for unscaled integer): ', 1)
                print('Decrypted output:', Fraction(engine.decrypt(c),divisor))
            else:
                print('Unknown choice.')
        except (ValueError, KeyError, OverflowError) as error:
            print('Operation refused:', error)


def main():
    print(__doc__)
    while True:
        print('\nBackend: 1 Paillier  2 Textbook RSA  3 Raw ElGamal')
        print('4 INSECURE bounded encrypted-bit experiment  0 Exit')
        mode = input('Choose: ').strip()
        if mode == '0':
            return
        if mode == '4':
            bits = integer('Toy key bits (128..65536; try 4096 for small jobs): ',128,65536)
            engine = Bits(bits)
        elif mode in ('1','2','3'):
            bits = integer('Key bits (32..2048; small values are insecure): ',32,2048)
            print('Generating keys; safe-prime ElGamal can be slow.')
            engine = PHE({'1':'paillier','2':'rsa','3':'elgamal'}[mode],bits)
            print('All plaintext arithmetic is modulo', engine.modulus)
        else:
            continue
        session(engine)


if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('\nEnded. Session keys and registers are not saved.')
