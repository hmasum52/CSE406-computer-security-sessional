"""
author : Hasan Masum
id     : 1805052
Level  : 4 Term 1
Course : CSE406-Computer Security Sessional
Dept.  : CSE, BUET
"""
import socket
import json
import os
from rsa_1805052 import RSA
from aes_1805052 import AES


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

# main function
if __name__ == "__main__":
    # step 1: RSA key generation
    rsa = RSA(128)

    # create server
    s = create_server()

    # accept connection from client
    print("Waiting for Bob...")
    client, addr = s.accept()

    # Step 2: RSA key distributio
    # receive public key from bob
    print("Receiving public key from Bob...")
    bob_public_key = client.recv(BUFFER_SIZE)
    bob_public_key = json.loads(bob_public_key.decode())
    print(f"Public key received: {bob_public_key}")
    print()

    # send public key to bob
    print("Sending public key to Bob...")
    client.sendall(json.dumps(rsa.public_key).encode())
    print("Public key sent!")
    print()

    # use alice private key as secret key for AES
    key, _ = rsa.private_key
    key = str(key)
    aes = AES(key)
    print("AES key:", key)

    # rsa encryp the aes key 
    encrypted_aes_key = rsa.encrypt(key, bob_public_key)

    print("Encrypted AES key:", encrypted_aes_key)

    # send aes key to bob
    print("Sending AES key to Bob...")
    client.sendall(str(encrypted_aes_key).encode())
    print("AES key sent!")
    print()

    # message input
    message = input("Enter message: ")
    encrypted_message = aes.encrypt(message.encode())
    print("Encrypted message:", encrypted_message.decode(errors="ignore"))
    print()

    # send data to bob
    print("Sending data to Bob...")
    client.sendall(encrypted_message)
    print("Data sent!")

    # receive data from bob
    print("Waiting for Bob's reply...")
    data = client.recv(BUFFER_SIZE)
    print("Data received!")
    print("Encrypted data:", data.decode(errors="ignore"))

    # decrypt data
    reply = aes.decrypt(data)
    print(f"Bob's reply: {reply.decode()}")

