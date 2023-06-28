"""
author: Hasan Masum, 1805052,
Leve 4, term 1, Dept CSE,BUET
"""
"""
References:
    - https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
    - https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
    - https://en.wikipedia.org/wiki/Primitive_root_modulo_n
    - https://crypto.stackexchange.com/questions/56155/primitive-root-of-a-very-big-prime-number-elgamal-ds
    - https://en.wikipedia.org/wiki/Modular_exponentiation
    Diffie-Hellman Key Exchange
"""
import time
import random
from BitVector import *

# left to right binary exponentiation
# https://en.wikipedia.org/wiki/Modular_exponentiation#Right-to-left_binary_method
def mod_pow(a:int, b:int, m:int)->int:
    """
    Computes a^b mod m
    """
    res:int = 1
    a = a % m # base = base mod modulus
    while b > 0:
        if b & 1: # exponent is odd
            res = (res * a) % m
        # next bit of exponent
        b = b >> 1 # exponent = exponent / 2
        a = (a * a) % m # base = base^2 mod modulus
    return res


# Deterministic Miller–Rabin primality test
# https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Deterministic_variants
def test_primality(n:int)->bool:
    """
    Test primality of n using Determinitic Miller-Rabin primality test
    @param n>2, an odd integer to be tested for primality
    """
    if n <= 1:
        return False

    # step-1: Testing against small sets of bases
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41]
    if n in small_primes:
        return True # prime
    for prime in small_primes:
        if n % prime == 0:
            return False # composite

    # step-2: factoring out powers of 2 from n-1
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d >>=1

    # Run Miller-Rabin primality test k times
    #for _ in range(k):
    for a in small_primes:
        # a = random.randint(2, n - 2)
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False # composite

    return True # probably prime


# Generate a prime number of k bits
def gen_prime(k:int=128)->int:
    """
    Generates a prime number of k bits
    """
    while True:
        # first generate a random odd number of k bits
        bv = BitVector(intVal=0, size=k)
        bv = bv.gen_random_bits(k)
        bv[0] = 1 # set MSB to 1 to make sure it is k bits
        bv[k-1] = 1 # set LSB to 1 to make it odd

        # test for primality
        check = test_primality(int(bv))
        if check:
            return int(bv)

# Generate a primitive root modulo n
# https://en.wikipedia.org/wiki/Primitive_root_modulo_n
def gen_primitive_root(n:int)->int:
    """
    Generates a primitive root modulo n
    @param n>2, a prime number
    """
    # find prime factors of n-1
    # n-1 = 2^s * t
    s, t = 0, n - 1
    while t % 2 == 0:
        s += 1
        t >>= 1

    # find a primitive root modulo n
    # https://crypto.stackexchange.com/questions/56155/primitive-root-of-a-very-big-prime-number-elgamal-ds
    while True:
        g = random.randint(2, n - 1)
        if mod_pow(g, t, n) != 1:
            return g

class DeffieHellman:
    def __init__(self, p:int, g:int):
        """
        @param public modulus p>2,  a prime number
        @param public base g g, a primitive root modulo p
        """
        self.p = p
        self.g = g

    def gen_private_key(self)->int:
        """
        Generates a private key
        """
        return random.randint(2, self.p - 2)

    def gen_public_key(self, private_key:int)->int:
        """
        Generates a public key
        """
        return mod_pow(self.g, private_key, self.p)
    
    def gen_shared_key(self, private_key:int, public_key:int)->int:
        """
        Generates a shared key
        """
        return mod_pow(public_key, private_key, self.p)
    
    def gen_keys(self)->tuple:
        """
        Generates a private key and a public key
        """
        private_key = self.gen_private_key()
        public_key = self.gen_public_key(private_key)
        return private_key, public_key


print("Generating prime numbers p and q...")
start = time.time()
p = gen_prime(128)
end = time.time()
print("Time taken to generate p:", (end - start)*1000)
print("p =", p)
print()

print("Generating primitive root g...")
start = time.time()
g = gen_primitive_root(p)
end = time.time()
print("Time taken to generate g:", (end - start)*1000)
print("g =", g)


print("Generating private and public keys...")
start = time.time()

alice = DeffieHellman(p, g)
alice_private_key, alice_public_key = alice.gen_keys()
print("Alice's private key:", alice_private_key)
print("Alice's public key:", alice_public_key)
print()

bob = DeffieHellman(p, g)
bob_private_key, bob_public_key = bob.gen_keys()
print("Bob's private key:", bob_private_key)
print("Bob's public key:", bob_public_key)
print()
end = time.time()

# shared key
alice_shared_key = alice.gen_shared_key(alice_private_key, bob_public_key)
bob_shared_key = bob.gen_shared_key(bob_private_key, alice_public_key)
print("Alice's shared key:", alice_shared_key)
print("Bob's shared key:", bob_shared_key)

# number of bits in shared key
print("Number of bits in shared key:", len(bin(alice_shared_key)[2:]))
# hex representation of shared key
print("Hex representation of shared key:", hex(alice_shared_key))
# print hex representation of shared key in 4*4 column major matrix
def hex_matrix(n:int, rows:int, cols:int)->str:
    """
    Returns hex representation of n in rows*cols column major matrix
    """
    hex_str = hex(n)[2:]
    hex_str = '0'*(rows*cols - len(hex_str)) + hex_str
    hex_str = hex_str.upper()
    hex_str = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    return hex_str

print("Hex representation of shared key in 4*4 column major matrix:")
print(hex_matrix(alice_shared_key, 4, 4))
print()