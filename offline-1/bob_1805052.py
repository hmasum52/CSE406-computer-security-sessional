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

if __name__ == "__main__":

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

    print("received data: ", response)
    print()

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

    # convert data to json
    data = json.dumps(data)

    print("Sending BOB's public key to Alice...")
    # send data to Alice
    s.sendall(data.encode())
    print("Public key sent!")
    print()

    # generate shared key
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
        print("Waiting for encrypted message from Alice...")
        data = s.recv(BUFFER_SIZE).decode()
        print("Encrypted message received!")
        print("Encrypted message:", data)
        print()

        # decrypt message
        print("Decrypting message...")
        aes = AES(str(shared_key))
        message = aes.decrypt(data)
        print("Decrypted message:", message)
        print()
    else:
        print("Alice is not ready!")
    print()

    s.close()

