import socket
import json
import os
from aes_1705039 import aes_decrypt
from rsa_1705039 import rsa_decrypt

SERVER_PORT = 7777
BUFFER_SIZE = 4096
PRIV_KEY_FILE = "./Dont Open This/priv_key.txt"
PLAIN_TEXT_FILE = "./Dont Open This/text.txt"

def recv_all(s, buffer_size=BUFFER_SIZE):
	msg_arr = []
  
	while True:
		segment = s.recv(buffer_size)
		msg_arr += [segment.decode()]

		if len(segment) < buffer_size:
			break

	return "".join(msg_arr)


if __name__ == "__main__":

	# Received data over socket from Alice (as client)

  s = socket.socket()
  s.connect(('127.0.0.1', SERVER_PORT))

  response = json.loads(recv_all(s, BUFFER_SIZE))

	# Read private key provided by Alice

  priv_key = None
  while priv_key is None:  
    try:
      with open(PRIV_KEY_FILE, "r") as r:
        priv_key = json.loads(r.read())
    except FileNotFoundError:
      pass
  os.remove(PRIV_KEY_FILE)

	# Decrypt the response to get 
  
  decrypted_key = rsa_decrypt(response.get('encrypted_key'), priv_key)
  plain_txt = aes_decrypt(response.get('text'), decrypted_key)

  print(f"Received text: {plain_txt}")

  # Write plain text to folder for Alice

  with open(PLAIN_TEXT_FILE, "w") as w:
    w.write(json.dumps(plain_txt))
