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
BUFFER_SIZE = 1024

def recv_all(s, buffer_size=BUFFER_SIZE):
    msg = []
    while True:
        chunk = s.recv(buffer_size)
        msg += [chunk.decode()]

        if len(chunk) < buffer_size:
            break

    return "".join(msg)

# main 
if __name__ == "__main__":

    # create socket 
    s = socket.socket()

    # connect to server
    s.connect(('127.0.0.1', SERVER_PORT))

    rsa = RSA(128)

    # send public key to server
    print("Sending public key to server...")
    s.sendall(json.dumps(rsa.public_key).encode())
    print("Public key sent!")
    print()

    # receive alice public key
    print("Receiving public key from server...")
    alice_public_key = s.recv(BUFFER_SIZE)
    alice_public_key = json.loads(alice_public_key.decode())
    print(f"Public key received: {alice_public_key}")
    print()


    # receive encrypted aes key
    print("Waiting AES key from server...")
    encrypted_aes_key = s.recv(BUFFER_SIZE).decode()
    print("AES key received!")
    
    # decrypt aes key
    key = rsa.decrypt(eval(encrypted_aes_key))
    print(f"Decrypted AES key: {key}")
    print()

    # receive encrypted message
    print("Waiting for message from server...")
    encrypted_message = s.recv(BUFFER_SIZE)
    print("Message received!")
    print("Encrypted message:", encrypted_message.decode(errors="ignore"))

    # decrypt message
    aes = AES(key)
    message = aes.decrypt(encrypted_message)
    print(f"Message: {message.decode()}")
    print()

    # reply message
    reply = input("Enter reply: ")
    encrypted_reply = aes.encrypt(reply.encode())
    print("Encrypted reply:", encrypted_reply.decode(errors="ignore"))

    # send reply
    print("Sending reply to server...")
    s.sendall(encrypted_reply)
    print("Reply sent!")

    # close connection
    s.close()
