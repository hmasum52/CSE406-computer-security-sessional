import time
from BitVector import *
from math import gcd

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

def gen_prime(k):
    """Generate a prime number of size k bits"""
    while True:
        bv = BitVector(intVal=0, size=k)
        bv = bv.gen_random_bits(k)  
        bv[0] = 1 # Set MSB to 1 to ensure k bits
        bv[k-1] = 1 # Set LSB to 1 to ensure odd number
        res = bv.test_for_primality()
        if res != 0:
            return bv.int_val()

def gen_e(phi_n):
    """Generate a relative prime of n"""
    for e in range(2, phi_n):
        if gcd(e, phi_n) == 1:
            return e
    raise ValueError("No e found")


# https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
def moduler_multiplicative_inverse(x, m):
  inverse = BitVector(intVal=x).multiplicative_inverse(BitVector(intVal=m))
  if inverse is not None:
    return inverse.int_val()
  else:
    raise ValueError("No multiplicative inverse exists")

# # https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation
def gen_e_d_n(k:int):
    # generate two large prime p,q each of k/2 bit length
    p = gen_prime(k // 2)
    q = gen_prime(k // 2)

    # compute n = p*q
    n = p * q # n is of k bit length

    # comput phi(n)
    phi_n = (p - 1) * (q - 1)

    # choose e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1
    e = gen_e(phi_n)

    # compute d such that d*e = 1 mod phi(n)
    # i.e. d = e^-1 mod phi(n)
    d = moduler_multiplicative_inverse(e, phi_n)

    return e, d, n

class RSA:
    def __init__(self, k):
        self.k = k # key size
        self.e, self.d, self.n = gen_e_d_n(k)
        self.public_key = (self.e, self.n)
        self.private_key = (self.d, self.n)

    # https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Encryption
    def encrypt(self, msg:str):
        encrypted_msg = []
        for m in msg:
            encrypted_c = mod_pow(ord(m),self.e, self.n) # c = m^e mod n
            encrypted_msg.append(encrypted_c)
        return encrypted_msg
    
    def encrypt(self, msg:str, public_key):
        encrypted_msg = []
        for m in msg:
            encrypted_c = mod_pow(ord(m),public_key[0], public_key[1])
            encrypted_msg.append(encrypted_c)
        return encrypted_msg

    # https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Decryption
    def decrypt(self, msg):
        decrypted_msg = ""
        for c in msg:
            decrypted_c = mod_pow(c, self.d, self.n) # m = c^d mod n
            decrypted_msg += chr(decrypted_c)
        return decrypted_msg

if __name__ == "__main__":
    key_size = 128
    txt = "abcd"
    
    start = time.time()
    rsa = RSA(key_size)
    end = time.time()
    key_gen_time = end - start


    start = time.time()
    encrypted_txt = rsa.encrypt_str(txt)
    print(f"Encrypted text: {encrypted_txt}")
    end = time.time()
    encryption_time = end - start

    start = time.time()
    decrypted_txt = rsa.decrypt_str(encrypted_txt)
    print(f"Decrypted text: {decrypted_txt}\n")
    end = time.time()
    decryption_time = end - start
    print()

    print(f"Key generation time: {key_gen_time}")
    print(f"Encryption time: {encryption_time}")
    print(f"Decryption time: {decryption_time}")
    print()
    

