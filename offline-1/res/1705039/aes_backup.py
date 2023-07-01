'''
    References
    - https://en.wikipedia.org/wiki/AES_key_schedule
    - https://www.youtube.com/watch?v=rmqWaktEpcw
    - https://www.cryptool.org/en/cto/aes-step-by-step
    - AES Encryption Simulation - slide
    - PKCS#7 padding  - https://www.youtube.com/watch?v=iZe_q3qW1cE
                    - https://www.youtube.com/watch?v=3OTMLUEPZUc

    Here will implement AES-128
    - 128 bit key
    - 128 bit plaintext
    - 128 bit ciphertext
    - 10 rounds
    - 16 bytes block size
'''

# pip install BitVector
import time

"""Tables"""

from BitVector import *
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

def str_to_hex(text: str):
    return BitVector(textstring=text).get_hex_string_from_bitvector()

class PaddingError(Exception):
    pass

# https://www.youtube.com/watch?v=3OTMLUEPZUc
def psck7_pad(b: bytes, block_size: int):
    pad_len = block_size - (len(b) % block_size)
    return b + pad_len * bytes([pad_len])

def psck7_unpad(b: bytes):
    pad_len = b[-1]
    if pad_len == 0 or len(b) < pad_len or not b.endswith(bytes([pad_len]) * pad_len):
        raise PaddingError("Invalid padding")
    return b[:-pad_len]

# AES class to encrypt and decrypt
class AES:
    # constructor with key and plaintext
    def __init__(self, key:str):
        self.key = key

        # padding key 
        self.key = psck7_pad(self.key.encode(), 16).decode()

        # convert key and plaintext to matrix
        self.key_matrix = self._constract_matrix(key)

        # generate round keys
        self.round_keys = self._generate_round_keys(print_round_keys=False)
        
    # construct a column major
    # matrix from a string of text
    def _constract_matrix(self, text: str):
        # 4 * 4 matrix column major 
        # matrix of hex value of text
        matrix = [[-1 for i in range(4)] for j in range(4)]

        # make column major matrix
        for j in range(4):
            for i in range(4):
                # matrix[i][j] = text[j*4 + i]
                # matrix[i][j] = hex(ord(text[j*4 + i]))
                matrix[i][j] = ord(text[j*4 + i])
        return matrix
    
    # print matrix
    def _print_matrix(self, matrix, text=""):
        if text != "":
            print(f"matrix of text: {text}")
        for i in range(4):
            for j in range(4):
                print(hex(matrix[i][j])[2:].upper().zfill(2), end=" ")
            print()
        print()

    # column matrix to string
    def _matrix_to_string(self, matrix):
        text = ""
        for j in range(4):
            for i in range(4):
                # text += chr(int(matrix[i][j], 16))
                text += hex(matrix[i][j])[2:].upper().zfill(2)+" "
            text += " "
        return text

    # print current state matrix
    def print_state_matrix(self):
        self._print_matrix(self.state_matrix)

    # print current state as plaintext
    def get_state_as_text(self):
        hex_str = self._matrix_to_string(self.state_matrix)
        text = ""
        for i in hex_str.split():
            text += chr(int(i, 16))
        return text

    def _rc(self, i:int, prev_rc:int) -> int:
        """
        https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants 
        return the rounding constant of 8 bit value
        @param i is the round number
        @param prev_rc is the previous round constant
        """
        if i == 1:
            return 0x01
        if prev_rc < 0x80:
            return 2 * prev_rc
        return (2 * prev_rc) ^ 0x11B 

    # substitute bytes
    def _g(self, w:int , rc:int) -> int:
        # circular bye left shift
        w = w[1:] + w[:1]

        # substitute bytes
        for i in range(4):
            w[i] = Sbox[w[i]]

        # add round constant
        w[0] = w[0] ^ rc
        return w

    # generate round keys
    # from the key_matrix
    def _generate_round_keys(self, print_round_keys=False):
        # round keys
        round_keys = []

        # first round key is the key itself
        round_keys.append(self.key_matrix)

        rc = 0x01 # rounding constant

        # generate 10 round keys
        for i in range(10):
            # get previous round key
            prev_round_key = round_keys[i]

            # get the last column of the previous round key
            last_col = [prev_round_key[j][3] for j in range(4)]

            rc = self._rc(i+1, rc) # get the rounding constant
            last_col = self._g(last_col, rc) # e.g w[3] = g(w[3])

            # get the first column of the previous round key
            # e.g. w[4] = w[0] xor g(w[3])
            first_col = [prev_round_key[j][0]^last_col[j] for j in range(4)]

            # get the second column of the previous round key
            # e.g. w[5] = w[1] xor w[4]
            second_col = [prev_round_key[j][1]^first_col[j] for j in range(4)]

            # get the third column of the previous round key
            # e.g. w[6] = w[2] xor w[5]
            third_col = [prev_round_key[j][2]^second_col[j] for j in range(4)]

            # e.g. w[7] = w[3] xor w[6]
            forth_col = [prev_round_key[j][3]^third_col[j] for j in range(4)]

            # create new round key
            # new_round_key = [first_col, second_col, third_col, last_col]
            new_round_key = []
            for j in range(4):
                new_round_key.append([
                    first_col[j], 
                    second_col[j], 
                    third_col[j], 
                    forth_col[j]])

            # append new round key
            round_keys.append(new_round_key)
        

        # print keys
        if print_round_keys:
            for i in range(11):
                print(f"round key {str(i).zfill(2)}: {self._matrix_to_string(self.round_keys[i])}")
            print()
        # return round keys
        return round_keys

    # add round key to current state matrix
    # @param key is the key matrix(column major)
    def add_round_key(self, key):
        # update state matrix
        for i in range(4):
            for j in range(4):
                self.state_matrix[i][j] ^= key[i][j]

    # substitute each entry (byte) of 
    # current state matrix by corresponding 
    # entry in AES S-Box
    def sub_bytes(self, inverse=False):
        sub_box = InvSbox if inverse else Sbox
        # update state matrix
        for i in range(4):
            for j in range(4):
                self.state_matrix[i][j] = sub_box[self.state_matrix[i][j]]

    # 4 rows are shifted cyclically to the left
    # by offsets of 0,1,2, and 3
    def shift_rows(self, inverse=False):
        # update state matrix
        for i in range(4):
            if inverse:
                self.state_matrix[i] = self.state_matrix[i][4-i:] + self.state_matrix[i][:4-i]
            else: self.state_matrix[i] = self.state_matrix[i][i:] + self.state_matrix[i][:i]

    # https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_MixColumns_step
    # https://en.wikipedia.org/wiki/Rijndael_MixColumns#Matrix_representation
    # Mix Column multiplies fixed matrix against current State Matrix
    def mix_columns(self, inverse=False):
        AES_modulus = BitVector(bitstring='100011011')
        new_state = [[0 for i in range(4)] for j in range(4)]
        for i in range(4):
            for j in range(4):
                val = 0;
                for k in range(4):
                    bv1 = BitVector(hexstring=hex(
                        self.state_matrix[k][j])[2:])
                    bv2 = Mixer[i][k] if not inverse else InvMixer[i][k]

                    bv3 = bv2.gf_multiply_modular(bv1, AES_modulus, 8)
                    val ^= bv3.int_val()
                new_state[i][j] = val
        self.state_matrix = new_state

        # encrypt plaintext
    def encrypt(self, plaintext:str, print_state=False):
        # add text padding if needed
        self.plaintext = psck7_pad(plaintext.encode("utf-8"), 16).decode("utf-8") #self._padding(plaintext)
        # print(f"padded plaintext: {self.plaintext}")

        chipher_text = ""
        for i in range(0, len(self.plaintext), 16):
            block = self.plaintext[i:i+16]
            self.state_matrix = self._constract_matrix(block)

            if print_state: print("Intial state: "); self.print_state_matrix()

            # round 0
            self.add_round_key(self.round_keys[0])

            if print_state: print("round 0:"); self.print_state_matrix()

            # round 1 to 9
            for i in range(1, 10):
                self.sub_bytes()
                self.shift_rows()
                self.mix_columns()
                self.add_round_key(self.round_keys[i])

                if print_state: print(f"round {i}:"); self.print_state_matrix()
                
            # round 10
            self.sub_bytes()
            self.shift_rows()
            self.add_round_key(self.round_keys[10])

            if print_state: print("round 10:"); self.print_state_matrix()

            # get ciphertext
            chipher_text += self.get_state_as_text()

        return chipher_text

    # decrypt ciphertext
    def decrypt(self, encryptedtext, print_state=False):

        # decrypt ciphertext
        decypted_text = ""
        for i in range(0, len(encryptedtext), 16):
            block = encryptedtext[i:i+16]
            self.state_matrix = self._constract_matrix(block)

            # round 10 
            self.add_round_key(self.round_keys[10])

            if print_state: print("round 10:"); self.print_state_matrix()

            # round 9 to 1
            for i in range(9, 0, -1):
                self.shift_rows(inverse=True)
                self.sub_bytes(inverse=True)
                self.add_round_key(self.round_keys[i])
                self.mix_columns(inverse=True)

                if print_state: print(f"round {i}:"); self.print_state_matrix()

            # round 0
            self.shift_rows(inverse=True)
            self.sub_bytes(inverse=True)
            self.add_round_key(self.round_keys[0])

            decypted_text += self.get_state_as_text()

        # self._unpadding(decypted_text)
        # print("decyprted: ", decypted_text)
        decypted_text = psck7_unpad(decypted_text.encode()).decode()

        return decypted_text

    def encrypt_file(self , input_file):
        print("Opening file...", input_file)
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        f.close()
        print("Encrypting file...")
        encrypted_text = self.encrypt(plaintext.decode("utf-8"))
        print("done")
        return encrypted_text
    
    # encrypt binary file
    def encrypt_binary_file(self, input_file, output_file):
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        encrypted_text = self.encrypt(plaintext)
        return encrypted_text

def text_test(key: str):
    # plaintext = "Two One Nine Two"
    plaintext = "Can They Do This BOB"

    start = time.time() # start time
    aes = AES(key)
    end = time.time() # end time
    key_schedule_time = end - start

    print("Plain text:")
    print("In ASCII: ", plaintext)
    print("In HEX: ", str_to_hex(plaintext).lower())
    print("")

    print("Key:")
    print("In ASCII: ", key)
    print("In HEX: ", str_to_hex(key).lower())
    print("")

    start = time.time() # start time
    encrypted_text = aes.encrypt(plaintext, print_state=False)
    end = time.time() # end time
    encrypt_time = end - start
    print("Chiper Text:")
    print("In ASCII: ", encrypted_text)
    print("In HEX: ", str_to_hex(encrypted_text).lower() )
    print("")

    start = time.time() # start time
    decypted_text = aes.decrypt(encrypted_text, print_state=False)
    end = time.time() # end time
    decrypt_time = end - start
    print("Dchiphered Text:")
    print("In ASCII: ", decypted_text)
    print("In HEX: ", str_to_hex(decypted_text).lower() )
    print("")

    print("Execution time details:")
    print("Key schedule: ", key_schedule_time, "seconds")
    print("Encryption Time: ", encrypt_time, "seconds")
    print("Decryption Time: ", decrypt_time, "seconds")

def text_file_test(key: str):
    aes = AES(key)
    input_file = "task2.txt"
    output_file = "task2_encrypted.txt"

    print("Encrypting file: ", input_file)
    encrypted_text = aes.encrypt_file(input_file)
    print("Encryption done.")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(encrypted_text)
    print("Encrypted text saved in file: ", output_file)

    input_file = "task2_encrypted.txt"
    # open input file
    with open (input_file, 'r', encoding='utf-8') as f:
        encrypted_text = f.read()
    
    decrypted_text = aes.decrypt(encrypted_text)

    output_file = "task2_decrypted.txt"
    with open(output_file, 'w', encoding="utf-8") as f:
        f.write(decrypted_text)
    print("Decrypted text saved in file: ", output_file)

def binary_file_test(key: str):
    pass


# main 
if __name__ == "__main__":

    # key = "Thats my Kung Fu"
    key = "BUET CSE18 Batch"

    text_file_test(key)



