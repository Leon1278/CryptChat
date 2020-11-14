from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto import Random
import sys

class AesEncryptor:

    def __init__(self, key=get_random_bytes(32)):
        self.enc_message = ""
        self.key = key

    def pad(self, s):
        return s + b'\0' * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message):
        self.iv = Random.new().read(AES.block_size)
        self.aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        self.enc_message = self.pad(message.encode('UTF-8'))
        self.ciphertext = self.aes.encrypt(self.enc_message)
        return self.iv + self.ciphertext

    def decrypt(self, cipher):
        self.iv = cipher[:AES.block_size]
        self.aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        self.cipher = cipher
        self.plaintext = self.aes.decrypt(cipher[AES.block_size:])
        return self.plaintext.rstrip(b'\0')