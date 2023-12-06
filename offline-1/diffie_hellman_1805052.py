"""
author : Hasan Masum
id     : 1805052
Level  : 4 Term 1
Course : CSE406-Computer Security Sessional
Dept.  : CSE, BUET
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
from tabulate import tabulate

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

# Generate list of n primes each of k bits
def gen_n_primes(n:int, k:int):
    """
    Generates a list of n primes each of k bits
    """
    primes = []
    for _ in range(n):
        primes.append(gen_prime(k))
    return primes
    

# p will be safe prime
# https://crypto.stackexchange.com/questions/56155/primitive-root-of-a-very-big-prime-number-elgamal-ds
def gen_public_modulus_p(k:int=128):
    """
    Generates a public modulus p which is also prime
    returns p, list of the factors of p-1
    """
    # generate 16 primes each of k/8 bits
    primes = gen_n_primes(8, k//8)
    # primes = [gen_prime(k-1)]
    primes.append(2)
    # primes = [gen_prime(k-1), 2] # factors of p-1
    p = 1
    for prime in primes:
        p *= prime
    p += 1 # p = 2 * product of primes + 1

    while not test_primality(p) or p.bit_length() != k:
        return gen_public_modulus_p(k)
    return p, primes


# https://en.wikipedia.org/wiki/Primitive_root_modulo_n#Finding_primitive_roots
def is_primitive_root(g:int, p:int, factors)->bool:
    """
    Checks if g is a primitive root modulo p
    @param g, an integer
    @param p, a prime number
    @param factors, a list of prime factors of p-1
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
def gen_public_base_g(p:int, factors, min, max)->int:
    """
    Generates a primitive root modulo p.
    @param n>p, a prime number
    @param factors, a list of prime factors of p-1
    """
    
    while True:
        g = random.randint(min, max)
        if is_primitive_root(g, p, factors):
            return g



class DiffieHellman:
    """
    Deffie-Hellman key exchange protocol
    Generates a public modulus p and a primitive root g modulo p
    when a new instance is created.
    """
    def __init__(self, p:int, g:int, k:int=128):
        """
        @param public modulus p>2,  a prime number
        @param public base g g, a primitive root modulo p
        @param k, number of bits of p
        """
        self.p = p
        self.g = g
        self.k = k

        start = time.time()
        self.private_key = gen_prime(self.k // 2) # a or b (64 bit)
        end = time.time()
        self.pk_gen_time_ms = (end - start)*1000 # ms

        # A = g^a mod p or B = g^b mod p
        start = time.time()
        self.public_key = mod_pow(self.g, self.private_key, self.p) # A = g^a mod p or B = g^b mod p
        end = time.time()
        self.pubk_gen_time_ms = (end - start)*1000 # ms
    
    # generate shared key
    # e.g. K = B^a mod p or K = A^b mod p
    # or K = g^(ab) mod p
    def gen_shared_key(self, others_key:int)->int:
        """
        Generates a shared key
        """
        key = mod_pow(others_key, self.private_key, self.p)
        return key

def run_diffie_hellman(k: int=128):
    ######################################
    print("Generating public modulus p...")
    start = time.time()
    p, factors = gen_public_modulus_p()
    end = time.time()
    p_gen_time_ms = (end - start)*1000 # ms
    print("Time taken to generate p:", p_gen_time_ms, "ms")
    print("p =", p)
    # number of bits in p
    print("Number of bits in p:",p.bit_length())
    print()
    ######################################

    print("Generating primitive root g...")
    start = time.time()
    g = gen_public_base_g(p, factors, 2, p-2)
    end = time.time()
    g_gen_time_ms = (end - start)*1000 # ms
    print("Time taken to generate g:", g_gen_time_ms, "ms")
    print("g =", g)
    # number of bits in g
    print("Number of bits in g:",g.bit_length())
    print()

    ######################################

    print("Generating private and public keys for Alice...")
    alice = DiffieHellman(p, g)
    print("private key:", alice.private_key)
    print("length:", alice.private_key.bit_length(), "Gen time: ", alice.pk_gen_time_ms, "ms")
    print("public key:", alice.public_key)
    print("public key length:", alice.public_key.bit_length())
    print()

    ######################################
    
    bob = DiffieHellman(p, g)
    print("Bob's public key:", bob.public_key)
    print("Bob's public key length:", bob.public_key.bit_length())
    print("Bob's private key:", bob.private_key)
    print("Bob's private key length:", bob.private_key.bit_length())
    print()

    ######################################

    # # shared key
    alice_shared_key = alice.gen_shared_key(bob.public_key)
    print("Alice's shared key:", alice_shared_key)
    print("Alice's shared key length:", alice_shared_key.bit_length())
    print()

    start = time.time()
    bob_shared_key = bob.gen_shared_key(alice.public_key)
    end = time.time()
    shared_key_gen_time_ms = (end - start)*1000 # ms
    print("Bob's shared key:", bob_shared_key)
    print("Bob's shared key length:", bob_shared_key.bit_length())
    
    return [k, p_gen_time_ms, g_gen_time_ms,
            alice.pk_gen_time_ms, alice.pubk_gen_time_ms,
            bob.pk_gen_time_ms, bob.pubk_gen_time_ms,
            shared_key_gen_time_ms]

# run diffie hellman train number of time and take average
def run_diffie_hellman_avg(k: int, trail: int):
    times = [0] * 7  # Initialize a list to store the accumulated times

    for _ in range(trail):
        res = run_diffie_hellman(k)
        times = [t + r for t, r in zip(times, res[1:8])]  # Accumulate the times

    times = [t / trail for t in times]  # Calculate the average times

    return [k] + times


if __name__ == "__main__":
    table = [["k", "p(ms)", "g(ms)","alice a", 
            "alice A", "bob b", "bob B", "shared key"]]
    for k in [128, 192, 256]:
        table.append(run_diffie_hellman_avg(k, 5))

    print()
    print(tabulate(table, headers="firstrow", tablefmt="grid"))