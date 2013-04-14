from Crypto.Cipher import AES
from Crypto import Random

# we'll be using a 256 bit key (32 bytes)
# key should be a byte string
# Cipher-Block Chaining mode of operation
def aes_encrypt(key, input):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = iv + cipher.encrypt(input)
    return msg

def aes_decrypt(key, input):
    iv = input[:16] # 16 or 15?
    enc = input[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(enc)
    return plaintext
