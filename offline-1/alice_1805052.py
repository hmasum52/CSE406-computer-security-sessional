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
BUFFER_SIZE = 1024

def create_server() -> socket : 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # bind socket to port
    s.bind(('', SERVER_PORT))
    s.listen(5)
    return s

# function to save string in text file
def save_string_to_file(filename: str, string: str):
    with open(filename, "w") as f:
        f.write(string)
        f.close()

def save_private_key(key, file_name):
    print("Saving private key to file...")
    if not os.path.isdir(SECRET_DIR):
        os.mkdir(SECRET_DIR)
    save_string_to_file(
        os.path.join(SECRET_DIR,"alice_priv_key.txt"),
        str(alice.private_key))
    print("Private key saved to file!")
    print()

if __name__ == "__main__":
    # generate p and g
    p, primes = gen_public_modulus_p()
    g = gen_public_base_g(p, primes, 2, p-2)
    

    # Generate private and public keys for Alice
    alice = DeffieHellman(p, g)
    print("Alice's private key:", alice.private_key)
    print("Alice's public key:", alice.public_key)

    # save private key to file
    save_private_key(alice.private_key, "alice_priv_key.txt")

    A = alice.public_key # g^a mod p

    # create data
    data = {
        "p": p,
        "g": g,
        "A": A
    }

    # create socket
    s = create_server()
    print("Waiting for Bob ...")
    client, addr = s.accept() # Blocking call
    print("Bob is here!")
    print()

    # send data to bob
    print("Sending p,g,A to Bob...")
    client.sendall(json.dumps(data).encode())
    print("p,g,A sent!")
    print()

    # receive data from bob
    print("Waiting for Bob's public key...")
    data = client.recv(BUFFER_SIZE).decode()
    data = json.loads(data)
    B = data["B"]
    print("Bob's public key received!")
    print("Bob's public key:", B)
    print()


    # compute shared secret key
    shared_key = alice.gen_shared_key(B)
    print("Alice's shared secret key:", shared_key)

    # save shared key to file
    print("Saving shared key to file...")
    save_string_to_file(
        os.path.join(SECRET_DIR,"alice_shared_key.txt"),
        str(shared_key))
    print("Shared key saved to file!")
    print()
    
    # inform bob that alice is ready to send message
    print("Sending ready message to Bob...")
    client.sendall("ready".encode())
    print("Ready message sent!")
    print()

    # receive ready message from bob
    print("Waiting for Bob to be ready...")
    data = client.recv(BUFFER_SIZE).decode()
    if data == "ready":
        print("Bob is ready!")

        # send message to bob
        print("Sending message to Bob...")
        message = "Hello from the other side Bob. How are you! This is Alice"
        print("Original Message:", message)
        aes = AES(str(shared_key))
        encrypted_message = aes.encrypt(message.encode())
        print("Encrypted message:", encrypted_message.decode(errors="ignore"))
        client.sendall(encrypted_message) # send bytes
        print("Message sent!")
        print()
    else:
        print("Bob is not ready!")

    client.close()


