import time
from BitVector import *
from math import gcd

KEY_SIZE = 128

def gen_prime(k):

  while True:
    bv = BitVector(intVal=0, size=k)
    bv = bv.gen_random_bits(k)  

    # Set MSB and LSB to 1
    bv[0] = 1
    bv[k-1] = 1

    check = bv.test_for_primality()
    if check != 0:
      return int(bv)


def gen_rel_prime(n):

  for val in range(2, (n // 2) + 1):
    if gcd(val, n) == 1:
      return val

  raise ValueError("No relative prime found")


def mul_inverse(x, m):
  bv = BitVector(intVal=x) 
  bv_modulus = BitVector(intVal=m)
  bv_result = bv.multiplicative_inverse(bv_modulus)

  if bv_result is not None:
    return int(bv_result)
  else:
    raise ValueError("No multiplicative inverse exists")


def gen_rsa_key_pair(k):
  
  p = gen_prime(k // 2)
  q = gen_prime(k // 2)

  n = p * q
  phi_n = (p - 1) * (q - 1)

  e = gen_rel_prime(phi_n)
  d = mul_inverse(e, phi_n)

  return {"d": d, "n": n}, {"e": e, "n": n}


def rsa_encrypt(msg, key):
  encrypted_msg = []

  for c in msg:
    encrypted_c = pow(ord(c), key['e'], key['n'])
    encrypted_msg.append(encrypted_c)

  return encrypted_msg


def rsa_decrypt(msg, key):
  decrypted_msg = ""

  for c in msg:
    decrypted_c = pow(c, key['d'], key['n'])
    decrypted_msg += chr(decrypted_c)

  return decrypted_msg


if __name__ == "__main__":
  
  key_size = int(sys.argv[1]) if len(sys.argv) >= 2 else KEY_SIZE
  txt = sys.argv[2] if len(sys.argv) >= 3 else "tahmeed"

  time_1 = time.time()

  priv_key, pub_key = gen_rsa_key_pair(key_size)
  time_2 = time.time()

  encrypted_txt = rsa_encrypt(txt, pub_key)
  time_3 = time.time()

  decrypted_txt = rsa_decrypt(encrypted_txt, priv_key)
  time_4 = time.time()

  # print(f"{txt=}")
  # print(f"{pub_key=}, {priv_key}")
  print(f"Key generation time: {time_2 - time_1}")
  # print(f"{encrypted_txt=}")
  print(f"Encryption time: {time_3 - time_2}")
  # print(f"{decrypted_txt=}")
  print(f"Decryption time: {time_4 - time_3}")
