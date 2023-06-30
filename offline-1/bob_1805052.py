import socket
import json
import os
from aes_1805052 import AES
from diffie_hellman_1805052 import DeffieHellman

SERVER_PORT = 5252
BUFFER_SIZE = 1024
SECRET_DIR = "secret"

def recv_all(s, buffer_size=BUFFER_SIZE):
    msg_arr = []
  
    while True:
        segment = s.recv(buffer_size)
        msg_arr += [segment.decode()]

        if len(segment) < buffer_size:
            break

    return "".join(msg_arr)

# function to save string in text file
def save_string_to_file(filename: str, string: str):
    with open(filename, "w") as f:
        f.write(string)
        f.close()

def connect_to_alice():
    # Received data over socket from Alice (as client)
    s = socket.socket()
    s.connect(('127.0.0.1', SERVER_PORT))

    print("Receiving data from Alice...")
    response = json.loads(recv_all(s, BUFFER_SIZE))
    print("Data received!")

    # json to python object
    p = response.get('p')
    g = response.get('g')
    A = response.get('A')

    return s, p, g, A

def generate_share_key(s, p, g):
    # generate private and public keys for Bob
    bob = DeffieHellman(p, g)
    print("Bob's private key:", bob.private_key)
    print("Bob's public key:", bob.public_key)
    print()

    # save bobs private key to file
    print("Saving private key to file...")
    if not os.path.isdir(SECRET_DIR):
        os.mkdir(SECRET_DIR)
    save_string_to_file(
        os.path.join(SECRET_DIR, "bob_priv_key.txt"),
        str(bob.private_key))
    print("Private key saved to file!")
    print()

    B = bob.public_key # g^b mod p

    # create data
    data = {
        "B": B
    }

    print("Sending BOB's public key to Alice...")
    # send data to Alice
    s.sendall(json.dumps(data).encode())
    print("Public key sent!")
    print()

    return bob

def generate_shared_key(bob:DeffieHellman, A:int):
    print("Generating shared key...")
    shared_key = bob.gen_shared_key(A)
    print("Shared key:", shared_key)

    # save shared key to file
    print("Saving shared key to file...")
    save_string_to_file(
        os.path.join(SECRET_DIR, "bob_shared_key.txt"),
        str(shared_key))
    print("Shared key saved to file!")
    print()

    return shared_key

if __name__ == "__main__":

    # s is alice socket
    s, p, g, A = connect_to_alice()
    
    # generate private and public keys for Bob
    # and share the public key with Alice
    bob:DeffieHellman = generate_share_key(s, p, g)

    # generate shared key
    shared_key = generate_shared_key(bob, A)

    # get ready message from Alice
    print("Waiting for Alice to send ready message...")
    data = s.recv(BUFFER_SIZE).decode()
    if data == "ready":
        print("Alice is ready!")
        print()

        # send ready message to Alice
        print("Sending ready message to Alice...")
        s.sendall("ready".encode())
        print("Ready message sent!")
        print()

        # receive encrypted message from Alice
        while True:
            print("Waiting for encrypted message from Alice...")
            data:bytes = s.recv(BUFFER_SIZE) # received encrypted message as bytes
            print("Encrypted message received!")
            print("Encrypted message:", data.decode(errors="ignore"))
            print()

            # decrypt message
            print("Decrypting message...")
            aes = AES(str(shared_key))
            message = aes.decrypt(data).decode()
            print("Decrypted message:", message)
            print()

            if message == "text":
                continue # receive a text
            elif message == "file":
                pass # receive a file
            elif message == "exit":
                print("Alice left the conversatoin!")
                break
    else:
        print("Alice is not ready!")
    print()

    s.close()

