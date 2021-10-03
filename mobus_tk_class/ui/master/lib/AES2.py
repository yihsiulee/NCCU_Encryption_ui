# https://asecuritysite.com/encryption/aes_modes
from Crypto.Cipher import AES
import hashlib
import sys
import binascii
import Padding
import base64


class AESCBC():

    def encrypt(self, plaintext, key, iv, mode=AES.MODE_CBC):
        plaintext=base64.b64encode(plaintext.encode('utf-8')).decode('ascii')
        plaintext=Padding.appendPadding(plaintext,blocksize=Padding.AES_blocksize,mode=0)
        iv = hex(iv)[2:8].zfill(16).encode()
        encobj = AES.new(key, mode, iv)
        return(encobj.encrypt(plaintext))

    def decrypt(self, ciphertext, key, iv, mode=AES.MODE_CBC):
        iv = hex(iv)[2:8].zfill(16).encode()
        encobj = AES.new(key, mode, iv)
        plaintext=encobj.decrypt(ciphertext)
        plaintext = Padding.removePadding(plaintext.decode(), mode=0)
        plaintext = base64.b64decode(plaintext).decode()
        return(plaintext)


if __name__ == "__main__":
    plaintext = input('please input message: ')
    key = input('key: ')
    key = hashlib.sha256(key.encode()).digest()
    AESCBC = AESCBC()
    print("Input data (CMS): "+binascii.hexlify(plaintext.encode()).decode())

    ciphertext = AESCBC.encrypt(plaintext, key, 2048)
    ciphertext= base64.b64encode(ciphertext)
    print("Cipher: ",ciphertext)
    plaintext = AESCBC.decrypt(base64.b64decode(ciphertext), key, 2048, AES.MODE_CBC)
    print("decrypt: "+plaintext)


    # plaintext = val
    # plaintext = Padding.appendPadding(
    #     plaintext, blocksize=Padding.AES_blocksize, mode=0)

    # ciphertext = encrypt2(plaintext.encode(), key, AES.MODE_CBC, iv.encode())
    # print("Cipher (CBC): "+binascii.hexlify(bytearray(ciphertext)).decode())

    # plaintext = decrypt2(ciphertext, key, AES.MODE_CBC, iv.encode())
    # plaintext = Padding.removePadding(plaintext.decode(), mode=0)
    # print("  decrypt: "+plaintext)


    # plaintext = val
    # plaintext = Padding.appendPadding(
    #     plaintext, blocksize=Padding.AES_blocksize, mode=0)

    # ciphertext = encrypt2(plaintext.encode(), key, AES.MODE_CFB, iv.encode())
    # print("Cipher (CFB): "+binascii.hexlify(bytearray(ciphertext)).decode())

    # plaintext = decrypt2(ciphertext, key, AES.MODE_CFB, iv.encode())
    # plaintext = Padding.removePadding(plaintext.decode(), mode=0)
    # print("  decrypt: "+plaintext)


    # plaintext = val
    # plaintext = Padding.appendPadding(
    #     plaintext, blocksize=Padding.AES_blocksize, mode=0)

    # ciphertext = encrypt2(plaintext.encode(), key, AES.MODE_OFB, iv.encode())
    # print("Cipher (OFB): "+binascii.hexlify(bytearray(ciphertext)).decode())

    # plaintext = decrypt2(ciphertext, key, AES.MODE_OFB, iv.encode())
    # plaintext = Padding.removePadding(plaintext.decode(), mode=0)
    # print("  decrypt: "+plaintext)
