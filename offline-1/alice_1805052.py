import socket 
import os 
import json
from diffie_hellman_1805052 import DeffieHellman, gen_public_modulus_p
from diffie_hellman_1805052 import gen_public_base_g
from diffie_hellman_1805052 import gen_public_modulus_p
from aes_1805052 import AES
"""
ALICE is the sender and BOB is the receiver. 
They will first agree on a shared secret key. 
For this, ALICE will send p, g and g^a(mod p) to BOB.

BOB, after receiving these, will send gb (mod p) to ALICE. Both will then
compute the shared secret key, store it and inform each other that they are ready for
transmission. 
"""

SERVER_PORT = 5252
KEY_SIZE = 128
SECRET_DIR = "secret"

# function to save string in text file
def save_string_to_file(filename: str, string: str):
    
    with open(filename, "w") as f:
        f.write(string)
        f.close()


if __name__ == "__main__":
    # generate p and g
    p, primes = gen_public_modulus_p()
    g = gen_public_base_g(p, primes, 2, p-2)
    

    # Generate private and public keys for Alice
    alice = DeffieHellman(p, g)
    print("Alice's private key:", alice.private_key)
    print("Alice's public key:", alice.public_key)

    # save private key to file
    if not os.path.isdir(SECRET_DIR):
        os.mkdir(SECRET_DIR)
    save_string_to_file(
        os.path.join(SECRET_DIR,"alice_priv_key.txt"),
        str(alice.private_key))

    A = alice.public_key # g^a mod p

    # create data
    data = {
        "p": p,
        "g": g,
        "A": A
    }

    # convert data to json
    data = json.dumps(data)

    # create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)