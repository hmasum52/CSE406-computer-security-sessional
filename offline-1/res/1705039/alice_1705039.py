import socket
import json
import os
from aes_1705039 import aes_encrypt
from rsa_1705039 import rsa_encrypt, gen_rsa_key_pair

SERVER_PORT = 7777
KEY_SIZE = 128
PRIV_KEY_DIR = "./Dont Open This"
PRIV_KEY_FILE = "./Dont Open This/priv_key.txt"
PLAIN_TEXT_FILE = "./Dont Open This/text.txt"

if __name__ == "__main__":  

  priv_key, pub_key = gen_rsa_key_pair(KEY_SIZE)

  # User input 

  txt = input("Enter txt: ")
  # txt = "Two One Nine Two" # 128 bits
  key = input("Enter key: ")
  # key = "Thats my Kung Fu" # 128 bits

  # Encrypt data for sending 

  cipher_txt = aes_encrypt(txt, key)
  print(f"Encrypted txt (AES): {cipher_txt}")

  encrypted_key = rsa_encrypt(key, pub_key)
  # print(f"Encrypted key (RSA): {encrypted_key}")

  data = {
    "text": cipher_txt,
    "encrypted_key": encrypted_key,
    "public_key": pub_key
  }

  # Write private key to folder for Alice

  if not os.path.isdir(PRIV_KEY_DIR):
    os.mkdir(PRIV_KEY_DIR)
  with open(PRIV_KEY_FILE, "w") as w:
    w.write(json.dumps(priv_key))

  # Send data over socket to Bob (as server)

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

  s.bind(('', SERVER_PORT))
  s.listen(5)
  print("Waiting for Bob ...")
  c, addr = s.accept() # Blocking call
  print("Successfully sent to Bob!")

  c.sendall(json.dumps(data).encode())

  c.close()

  # Read the plain text in folder from Bob

  recv_txt = None
  while recv_txt is None:  
    try:
      with open(PLAIN_TEXT_FILE, "r") as r:
        recv_txt = json.loads(r.read())
    except FileNotFoundError:
      pass
  os.remove(PLAIN_TEXT_FILE)

  # Compare the texts

  if recv_txt == txt:
    print(f"The texts match! ({txt})")
  else:
    print(f"Texts do not match! ({txt} != {recv_txt})")