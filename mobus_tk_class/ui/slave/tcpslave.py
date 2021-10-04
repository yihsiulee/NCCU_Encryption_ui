#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""
 Modbus TestKit: Implementation of Modbus protocol in python
 (C)2009 - Luc Jean - luc.jean@gmail.com
 (C)2009 - Apidev - http://www.apidev.fr
 This is distributed under GNU LGPL license, see license.txt
"""

from logging import raiseExceptions
import sys

# from nose import exc
from tcpmaster import TcpMaster

import modbus_tk
import modbus_tk.defines as cst
from modbus_tk import modbus_tcp
import pyDH
import time
import socket
import base64
import hashlib
import Padding
from speck import SpeckCipher
from simon import SimonCipher
import threading
from lib.AES import AEAD
from lib.AES2 import AESCBC
from lib.pypresent import Present
from lib import common


class TcpSlave():

    def __init__(self, host='127.0.0.1', port=7000, max_socket=5):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((host, port))
        self.socket.setblocking(False)
        self.max_socket = max_socket
        self.clients = []
        self.cipher = ""
        self.shared_key = 'b3e9917a43cc089c389cfd50e4d8bd6d316d72edcb73698ed0ffbe754506fa95'
        self.iv = None
        self.DH = pyDH.DiffieHellman(14)
        self.PK = self.DH.gen_public_key()
        t = threading.Thread(target=self.start_server)
        t.start()

    """
    用AES解密master傳來的資料

    Return: 
        result: 明文
    """

    def dec_AES(self):
        aescbc = AESCBC()
        ciphertext = base64.b64decode(self.cipher)
        key = hashlib.sha256(self.shared_key.encode()).digest()
        plaintext = aescbc.decrypt(ciphertext, key, self.iv)

        return ciphertext, str(plaintext)

    """
    用present解密master傳來的資料

    Return: 
        result: 明文
    """

    def dec_present(self):
        plaintexts = []
        key = self.shared_key[:20]
        key = bytes.fromhex(key)
        cipher = Present(key)
        ciphertext = bytearray(base64.b64decode(self.cipher))
        for i in range(8, len(ciphertext)+8, 8):
            plaintext = cipher.decrypt(ciphertext[i-8:i])
            plaintext = Padding.removePadding(
                plaintext.decode(), blocksize=8, mode='CMS')
            plaintext = base64.b64decode(plaintext).decode()
            plaintexts.append(plaintext)

        result = ''.join(plaintexts)

        return ciphertext, str(result)

    """
    用speck解密master傳來的資料

    Return: 
        result: 明文
    """

    def dec_speck(self):
        plaintexts = []
        key = self.shared_key[:32]
        key = int(key, 16)
        w = SpeckCipher(key, key_size=128, block_size=64)
        ciphertext = bytearray(base64.b64decode(self.cipher))
        for i in range(8, len(ciphertext)+8, 8):
            plaintext = w.decrypt(int.from_bytes(
                ciphertext[i-8:i], byteorder='big'))
            hexstr = hex(plaintext)
            plaintext = bytes.fromhex(hexstr[2:])
            plaintext = Padding.removePadding(
                plaintext.decode(), blocksize=8, mode='CMS')
            plaintext = base64.b64decode(plaintext).decode()
            plaintexts.append(plaintext)

        result = ''.join(plaintexts)
        return ciphertext, result

    """
    用simon解密master傳來的資料

    Return: 
        result: 明文
    """

    def dec_simon(self):
        plaintexts = []
        key = self.shared_key[:32]
        key = int(key, 16)
        w = SimonCipher(key, key_size=128, block_size=64)
        ciphertext = bytearray(base64.b64decode(self.cipher))
        for i in range(8, len(ciphertext)+8, 8):
            plaintext = w.decrypt(int.from_bytes(
                ciphertext[i-8:i], byteorder='big'))
            hexstr = hex(plaintext)
            plaintext = bytes.fromhex(hexstr[2:])
            plaintext = Padding.removePadding(
                plaintext.decode(), blocksize=8, mode='CMS')
            plaintext = base64.b64decode(plaintext).decode()
            plaintexts.append(plaintext)

        result = ''.join(plaintexts)
        return ciphertext, result

    def _get_key(self, m_pk):
        self.shared_key = self.DH.gen_shared_key(m_pk)
        print('generate share key:\t' + str(self.shared_key))

    """
    取得diffie hellman shared key(不需執行)
    Return:
        share: shared key
    """

    def get_key(self):
        return self.shared_key

    def start_server(self):
        self.socket.listen(5)
        print("listening")
        while True:
            try:

                client, addr = self.socket.accept()
                print('Client address:', addr)
                print('hi')
                self.clients.append(client)
            except Exception as e:
                pass
            for client in self.clients:
                try:
                    req = client.recv(8192)
                    if req.decode().startswith("dh:"):
                        self._get_key(int(req.decode().split(':')[1]))
                        client.send(str(self.PK).encode())
                    elif req.decode().startswith("iv:"):
                        self.iv = int(req.decode().split(':')[1])
                        print('iv=', self.iv)
                    else:
                        self.cipher = req
                        print('cypher=', req)
                        client.close()
                        self.clients.remove(client)
                        print('end')
                except Exception as e:
                    pass


def main():
    """main"""
    tcpslave = TcpSlave()
    while True:
        intext = input('please input message: ')
        if intext == 'aes':
            result = tcpslave.dec_AES()
            print(result)

        if intext == 'pre':
            result = tcpslave.dec_present()
            print(result)

        if intext == 'spe':
            result = tcpslave.dec_speck()
            print(result)

        if intext == 'sim':
            result = tcpslave.dec_simon()
            print(result)


if __name__ == "__main__":
    main()
