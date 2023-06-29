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
    - https://ahmed-tahir.medium.com/diffie-hellman-key-exchange-algorithm-in-python-97c2abc855a5
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
    # https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Testing_against_small_sets_of_bases
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
    # https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Miller_test
    for a in small_primes:
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

def is_primitive_root(g:int, p:int, factors)->bool:
    """
    Checks if g is a primitive root modulo p
    @param g, an integer
    @param p, a prime number
    """
    # check if g is a primitive root modulo p
    # https://en.wikipedia.org/wiki/Primitive_root_modulo_n#Finding_primitive_roots
    # step-1: compute phi(p) = p-1
    phi = p - 1 # Euler's totient function
    for prime in factors:
        if mod_pow(g, phi // prime, p) == 1:
            return False
    return True

# Generate a primitive root modulo n
# https://en.wikipedia.org/wiki/Primitive_root_modulo_n#Finding_primitive_roots
def gen_primitive_root(p:int, factors)->int:
    """
    Generates a primitive root modulo p.
    @param n>p, a prime number
    @param factors, a list of prime factors of p-1
    """
    
    while True:
        # generate a random number in [2, p-2]
        #  Exactly half of the integers from 2 to p−2 are primitives
        g = random.randint(2, p-2)
        if is_primitive_root(g, p, factors):
            return g


# Generate list of n primes each of k bits
def gen_n_primes(n:int, k:int):
    """
    Generates a list of n primes each of k bits
    """
    primes = []
    for _ in range(n):
        primes.append(gen_prime(k))
    return primes
    

def gen_public_modulus_p(k:int=128)->int:
    """
    Generates a public modulus p which is also prime
    """
    # generate 16 primes each of k/8 bits
    primes = gen_n_primes(8, k//8)

    # generate p form 16 primes
    p = 1
    for prime in primes:
        p *= prime
    primes.append(2)
    p = p*2 + 1 # make p odd

    while not test_primality(p) or p.bit_length() != k:
        return gen_public_modulus_p(k)
    return p, primes

class DeffieHellman:
    def __init__(self, p:int, g:int, k:int=128):
        """
        @param public modulus p>2,  a prime number
        @param public base g g, a primitive root modulo p
        @param k, number of bits of p
        """
        self.p = p
        self.g = g
        self.k = k
        self.private_key = gen_prime(self.k // 2) # a or b
        # A = g^a mod p or B = g^b mod p
        self.public_key = mod_pow(self.g, self.private_key, self.p) # A or B
        while self.public_key.bit_length() != self.k:
            self.private_key = gen_prime(self.k // 2)
            self.public_key = mod_pow(self.g, self.private_key, self.p)

    
    # generate shared key
    # e.g. K = B^a mod p or K = A^b mod p
    # or K = g^(ab) mod p
    def gen_shared_key(self, others_key:int)->int:
        """
        Generates a shared key
        """
        key = mod_pow(others_key, self.private_key, self.p)
        while key.bit_length() != self.k:
            return self.gen_shared_key(others_key)
        return key
    

if __name__ == "__main__":
    print("Generating public modulus p...")
    start = time.time()
    p, factors = gen_public_modulus_p()
    end = time.time()
    print("Time taken to generate p:", (end - start)*1000)
    print("p =", p)
    # number of bits in p
    print("Number of bits in p:",p.bit_length())
    print()


    print("Generating primitive root g...")
    start = time.time()
    g = gen_primitive_root(p, factors)
    end = time.time()
    print("Time taken to generate g:", (end - start)*1000)
    print("g =", g)
    # number of bits in g
    print("Number of bits in g:",g.bit_length())
    print()


    print("Generating private and public keys...")
    start = time.time()
    alice = DeffieHellman(p, g)
    print("Alice's public key:", alice.public_key)
    print("Alice's public key length:", alice.public_key.bit_length())
    print("Alice's private key:", alice.private_key)
    print("Alice's private key length:", alice.private_key.bit_length())
    print()

    
    bob = DeffieHellman(p, g)
    print("Bob's public key:", bob.public_key)
    print("Bob's public key length:", bob.public_key.bit_length())
    print("Bob's private key:", bob.private_key)
    print("Bob's private key length:", bob.private_key.bit_length())
    print()

    # # shared key
    alice_shared_key = alice.gen_shared_key(bob.public_key)
    print("Alice's shared key:", alice_shared_key)
    print("Alice's shared key length:", alice_shared_key.bit_length())
    print()

    bob_shared_key = bob.gen_shared_key(alice.public_key)
    print("Bob's shared key:", bob_shared_key)
    print("Bob's shared key length:", bob_shared_key.bit_length())




    # # print hex representation of shared key in 4*4 column major matrix
    # def hex_matrix(n:int, rows:int, cols:int)->str:
    #     """
    #     Returns hex representation of n in rows*cols column major matrix
    #     """
    #     hex_str = hex(n)[2:]
    #     hex_str = '0'*(rows*cols - len(hex_str)) + hex_str
    #     hex_str = hex_str.upper()
    #     hex_str = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    #     return hex_str

    # print("Hex representation of shared key in 4*4 column major matrix:")
    # print(hex_matrix(alice_shared_key, 4, 4))
    # print()