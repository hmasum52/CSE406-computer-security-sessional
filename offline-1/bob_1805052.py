import socket
import json
import os
from aes_1805052 import AES
from diffie_hellman_1805052 import DiffieHellman

SERVER_PORT = 5252
BUFFER_SIZE = 1024
SECRET_DIR = "secret"

def recv_json(s, buffer_size=BUFFER_SIZE):
    msg = []
    while True:
        chunk = s.recv(buffer_size)
        msg += [chunk.decode()]

        if len(chunk) < buffer_size:
            break

    return "".join(msg)

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
    response = json.loads(recv_json(s, BUFFER_SIZE))
    print("Data received!")

    # json to python object
    p = response.get('p')
    g = response.get('g')
    A = response.get('A')

    return s, p, g, A

def generate_share_key(s, p, g):
    # generate private and public keys for Bob
    bob = DiffieHellman(p, g)
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

def generate_shared_key(bob:DiffieHellman, A:int):
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

def receive_text(aes, s:socket):
    print("Waiting for encrypted message from Alice...")
    data:bytes = s.recv(BUFFER_SIZE) # received encrypted message as bytes
    print("Encrypted message received!")
    print("Encrypted message:", data.decode(errors="ignore"))
    print()

    # decrypt message
    print("Decrypting message...")
    message = aes.decrypt(data).decode()
    print("Decrypted message:", message)
    print()

    return message

def send_text(aes: AES, client: socket):
    message = input("Enter message: ")
    encrypted_message = aes.encrypt(message.encode())
    print("Encrypted message:", encrypted_message.decode(errors="ignore"))
    # send message to Alice
    print("Sending text message to Alice...")
    client.sendall(encrypted_message) # send bytes
    print("Message sent!")
    print()

def receive_and_save_file(aes:AES, s:socket):
    # get file name
    print("Waiting for file name from Alice...")
    file_name = aes.decrypt(s.recv(BUFFER_SIZE)).decode()
    print("File name received!")
    print("File name:", file_name)
    print()

    print("Waiting for encrypted file from Alice...")
    # receiv all data bytes
    data = b"" # bytes
    while True:
        chunk = s.recv(BUFFER_SIZE)
        data += chunk
        if len(chunk) < BUFFER_SIZE:
            break
    print("Encrypted file received!")
    # print("Encrypted file:", data.decode(errors="ignore"))
    print()

    # decrypt file
    print("Decrypting file...")
    file = aes.decrypt(data)
    print("File decrypted!")
    print()
    
    # save file
    print("Saving file...")
    with open(f"bob_{file_name}", "wb") as f:
        f.write(file)
        f.close()
    print("File saved!")
    print()

if __name__ == "__main__":

    # s is alice socket
    s, p, g, A = connect_to_alice()
    
    # generate private and public keys for Bob
    # and share the public key with Alice
    bob:DiffieHellman = generate_share_key(s, p, g)

    # generate shared key
    shared_key = generate_shared_key(bob, A)

    aes = AES(str(shared_key))

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
            message = receive_text(aes, s)
            if message == "text":
                _ = receive_text(aes, s)
                reply = input("Do you want to reply? (y/n): ")
                while reply != "y" and reply != "n":
                    print("Invalid input!")
                    reply = input("Do you want to reply? (y/n): ")
                if reply == "y":
                    send_text(aes, s)
            elif message == "file":
                receive_and_save_file(aes, s)
            elif message == "exit":
                print("Alice left the conversatoin!")
                break
    else:
        print("Alice is not ready!")
    print()

    s.close()

