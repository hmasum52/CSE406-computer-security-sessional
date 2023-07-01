'''
  References
  - https://en.wikipedia.org/wiki/AES_key_schedule
  - https://www.youtube.com/watch?v=rmqWaktEpcw
  - https://www.cryptool.org/en/cto/aes-step-by-step
  - AES Encryption Simulation - slide
'''

from BitVector import *
import time


Sbox = (
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
  0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
  0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
  0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
  0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
  0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
  0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
  0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
  0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
  0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
  0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
  0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
  0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
  0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
  0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
  0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

Mixer = [
  [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
  [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
  [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
  [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
  [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
  [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
  [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
  [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]

"""
  Key Expansion to 128-bit
"""
def pad_txt(txt):
  if len(txt) % 16 == 0:
    return txt

  extra_len = 16 - (len(txt) % 16)
  padding = "".join([chr(1) * extra_len])
  txt += padding
  return txt


def pad_key(key):
  if len(key) == 16:
    return key
  elif len(key) < 16:
    extra_len = 16 - len(key) % 16
    padding = "".join([chr(1) * extra_len])
    key += padding
    return key
  else:
    return key[:16]


def unpad_txt(txt):
  padding_len = 0
  for i in range(len(txt) - 1, 0, -1):
    if txt[i] != chr(1):
      break
    padding_len += 1

  if padding_len == 0:
    return txt
  else:
    return txt[:-padding_len]


def print_matrix(matrix, txt=""):
  if txt != "":
    print(f"Matrix (row-major): {txt}")

  for i, vec in enumerate(matrix):
    print(f"C{i}: | ", end="")
    for val in vec:
      print(f"{val:4} | ", end="")
    print("")


def key_expansion(key_matrix, n_rounds=10):
  # Param: key_matrix is a 4x4 2d array of hex strings
  assert len(key_matrix) == 4, "Key expansion input matrix size mismatch"
  rc = 0x1 # Round constant
  key_matrix_extended = key_matrix.copy()

  # Iterate for n (11/13/15) rounds 
  for _ in range(n_rounds):
    
    last_vector = key_matrix_extended[-1].copy()

    # Rotate word, shift 1 place forward
    last_vector.append(last_vector.pop(0))

    # Substitude word, using s-box per key
    for i in range(4):
      last_vector[i] = hex(Sbox[int(last_vector[i], 16)])

    # Add round constant
    last_vector[0] = hex(int(last_vector[0], 16) ^ rc)
    if rc < 0x80:
      rc = 2 * rc
    else:
      rc = (2 * rc) ^ 0x11b

    # Append the modified last vector (temporarily)
    # Will remove later, done for ease of iterative xor
    key_matrix_extended.append(last_vector)

    # Create 4 new vectors by iterative xor
    for _ in range(4):
      key_arr = []

      # Xor n th vector with n-4 th vector
      for k in range(4):
        key = hex(int(key_matrix_extended[-1][k], 16) ^ int(key_matrix_extended[-5][k], 16))
        key_arr.append(key)

      key_matrix_extended.append(key_arr)

    # Remove the modified vector from n-4 th place
    del key_matrix_extended[-5]

  assert len(key_matrix_extended) == (n_rounds + 1) * 4, "Key expansion result matrix size mismatch"

  return key_matrix_extended


def add_round_key(state_matrix, key_matrix):
  for i in range(4):
    for j in range(4):
      state_matrix[j][i] = hex(int(state_matrix[j][i], 16) ^ int(key_matrix[j][i], 16))


def construct_matrix(txt):
  matrix = [[-1 for _ in range(4)] for _ in range(4)]
  for i in range(4):
    for j in range(4):
      matrix[i][j] = hex(ord(txt[(i * 4) + j]))
  # print_matrix(matrix, txt)
  # print(matrix)
  print("")
  return matrix


def sub_bytes(state_matrix, inverse=False):
  box = Sbox if not inverse else InvSbox

  for i in range(4):
    for j in range(4):
      state_matrix[i][j] = hex(box[int(state_matrix[i][j], 16)])


def mix_columns(state_matrix, inverse=False):
  AES_modulus = BitVector(bitstring='100011011')
  new_state_matrix = [[-1 for _ in range(4)] for _ in range(4)]
  mixer = Mixer if not inverse else InvMixer

  for i in range(4):
    for j in range(4):
      val = 0

      for k in range(4):
        bv1 = BitVector(intVal=int(state_matrix[j][k], 16))
        bv2 = mixer[i][k]
        # Multiplicaiton per entry
        bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
        # XOR with entire vector
        val = val ^ int(bv3)
        
      new_state_matrix[j][i] = hex(val)
  
  return new_state_matrix

      
def aes_encrypt_16(txt, key):

  n_rounds = 10
  state_matrix = construct_matrix(txt)
  key_matrix = construct_matrix(key)

  key_matrix_extended = key_expansion(key_matrix, n_rounds)

  add_round_key(state_matrix, key_matrix_extended[0:4])

  for i_round in range(1, n_rounds + 1):
    # 1. Substitute bytes
    sub_bytes(state_matrix)

    # 2. Shift rows
    for i in range(4):
      for j in range(i):
        temp_val = state_matrix[0][i]
        state_matrix[0][i] = state_matrix[1][i]
        state_matrix[1][i] = state_matrix[2][i]
        state_matrix[2][i] = state_matrix[3][i]
        state_matrix[3][i] = temp_val

    # 3. Mix columns
    if i_round != n_rounds:
      state_matrix = mix_columns(state_matrix)

    # 4. Add round keys
    add_round_key(state_matrix, key_matrix_extended[i_round * 4:(i_round + 1) * 4])
    
    # print_matrix(state_matrix, f"after round {i_round}")

  cipher_txt = ""
  for i in range(4):
    for j in range(4):
      cipher_txt += chr(int(state_matrix[i][j], 16))

  return cipher_txt


def aes_decrypt_16(txt, key):

  n_rounds = 10
  state_matrix = construct_matrix(txt)
  key_matrix = construct_matrix(key)

  key_matrix_extended = key_expansion(key_matrix, n_rounds)

  add_round_key(state_matrix, key_matrix_extended[(n_rounds * 4):(n_rounds + 1) * 4])

  for i_round in range(n_rounds - 1, -1, -1):

    # 1. Inverse shift rows
    for i in range(4):
      for j in range(i):
        temp_val = state_matrix[3][i]
        state_matrix[3][i] = state_matrix[2][i]
        state_matrix[2][i] = state_matrix[1][i]
        state_matrix[1][i] = state_matrix[0][i]
        state_matrix[0][i] = temp_val

    # 2. Inverse substitute bytes
    sub_bytes(state_matrix, inverse=True)

    # 3. Add round keys
    add_round_key(state_matrix, key_matrix_extended[i_round * 4:(i_round + 1) * 4])

    # 4. Inverse mix columns
    if i_round != 0:
      state_matrix = mix_columns(state_matrix, inverse=True)

  plain_txt = ""
  for i in range(4):
    for j in range(4):
      plain_txt += chr(int(state_matrix[i][j], 16))

  return plain_txt


def aes_encrypt(plain_txt, key):
  plain_txt = pad_txt(plain_txt)
  key = pad_key(key)
  assert len(plain_txt) % 16 == 0, "Text length not a multiple of 16"
  assert len(key) == 16, "Length of key not 16"
  
  txt_arr = [plain_txt[i:i + 16] for i in range(0, len(plain_txt), 16)]
  encrypted_txt = ""

  for txt in txt_arr:
    encrypted_txt += aes_encrypt_16(txt, key)

  return encrypted_txt


def aes_decrypt(cipher_txt, key):
  key = pad_key(key)
  assert len(cipher_txt) % 16 == 0, "Text length not a multiple of 16"
  assert len(key) == 16, "Length of key not 16"
  
  txt_arr = [cipher_txt[i:i + 16] for i in range(0, len(cipher_txt), 16)]
  decrypted_txt = ""

  for txt in txt_arr:
    decrypted_txt += aes_decrypt_16(txt, key)

  
  decrypted_txt = unpad_txt(decrypted_txt)
  return decrypted_txt


if __name__ == "__main__":
  key = "Thats my Kung Fu" # 128 bits
  txt = "Two One Nine Two" # 128 bits
  
  key_matrix = construct_matrix(key)
  time_1 = time.time()

  key_matrix_extended = key_expansion(key_matrix)
  time_2 = time.time()
  
  cipher_txt = aes_encrypt(txt, key)
  time_3 = time.time()

  plain_txt = aes_decrypt(cipher_txt, key)
  time_4 = time.time()
  
  print(f"text: {txt}")
  print(f"key: {key}")
  print(f"Key generation time: {time_2 - time_1}s")
  print(f"ciphertext: {cipher_txt}")
  print(f"Encryption time: {time_3 - time_2}s")
  print(f"plaintext: {plain_txt}")
  print(f"Decryption time: {time_4 - time_3}s")
