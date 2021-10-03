#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""
 Modbus TestKit: Implementation of Modbus protocol in python
 (C)2009 - Luc Jean - luc.jean@gmail.com
 (C)2009 - Apidev - http://www.apidev.fr
 This is distributed under GNU LGPL license, see license.txt
"""

from __future__ import print_function
from ctypes import byref
from http import client
from logging import raiseExceptions
import modbus_tk
import modbus_tk.defines as cst
from modbus_tk import modbus_tcp, hooks
import pyDH
import logging
import sys
import hashlib
import time
import secrets
import base64
import Padding
from speck import SpeckCipher
from simon import SimonCipher
import socket
from lib.AES2 import AESCBC
from lib.pypresent import Present
from lib import common


class TcpMaster():

    def __init__(self, host='127.0.0.1', port=7000, max_socket=5):
        self.host = host
        self.port = port

    """
    用AES加密
    Args:
        values:list of values ex."[5]"
    Return:
        ciphertext:密文
    """

    def enc_AES(self, value):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect((self.host, self.port))
        self._get_key()
        value = value[0]
        aescbc = AESCBC()
        iv = secrets.randbelow(2048)
        temp = "iv:"+str(iv)
        self.socket.send(temp.encode())
        key = hashlib.sha256(self.shared_key.encode()).digest()
        ciphertext = aescbc.encrypt(value, key, iv)
        self.socket.send(base64.b64encode(ciphertext))
        self.socket.close()

        return ciphertext

    """
    用present加密
    Args:
        values:list of values ex."[5]"
    Return:
        encrypted:密文
    """

    def enc_present(self, value):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect((self.host, self.port))
        self._get_key()
        value = value[0]
        values = [char for char in value]
        encrypteds = bytearray()
        for i in values:
            key = self.shared_key[:20]
            key = bytes.fromhex(key)
            cipher = Present(key)
            plaintext = base64.b64encode(i.encode('utf-8')).decode('ascii')
            plaintext = Padding.appendPadding(
                plaintext, blocksize=8, mode='CMS')
            encrypted = cipher.encrypt(plaintext.encode())
            encrypteds.extend(encrypted)
        self.socket.send(base64.b64encode(encrypteds))
        self.socket.close()

        return encrypted

    """
    用speck加密
    Args:
        values:list of values ex."[5]"
    Return:
        encrypteds:密文
    """

    def enc_speck(self, values):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect((self.host, self.port))
        self._get_key()
        value = values[0]
        values = [char for char in value]
        encrypteds = bytearray()
        for i in values:
            key = self.shared_key[:32]
            key = int(key, 16)
            w = SpeckCipher(key, key_size=128, block_size=64)
            plaintext = base64.b64encode(i.encode('utf-8')).decode('ascii')
            plaintext = Padding.appendPadding(
                plaintext, blocksize=8, mode='CMS')
            encrypted = w.encrypt(int.from_bytes(
                plaintext.encode(), byteorder='big'))
            encrypted = bytes.fromhex(hex(encrypted)[2:])
            encrypteds.extend(encrypted)
        self.socket.send(base64.b64encode(encrypteds))
        self.socket.close()
        return encrypteds

    """
    用simon加密
    Args:
        values:list of values ex."[5]"
    Return:
        encrypteds:密文
    """

    def enc_simon(self, values):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect((self.host, self.port))
        self._get_key()
        value = values[0]
        values = [char for char in value]
        encrypteds = bytearray()
        for i in values:
            key = self.shared_key[:32]
            key = int(key, 16)
            w = SimonCipher(key, key_size=128, block_size=64)
            plaintext = base64.b64encode(i.encode('utf-8')).decode('ascii')
            plaintext = Padding.appendPadding(
                plaintext, blocksize=8, mode='CMS')
            encrypted = w.encrypt(int.from_bytes(
                plaintext.encode(), byteorder='big'))
            encrypted = bytes.fromhex(hex(encrypted)[2:])
            encrypteds.extend(encrypted)
        self.socket.send(base64.b64encode(encrypteds))
        self.socket.close()
        return encrypteds


    def _get_key(self):
        DH = pyDH.DiffieHellman(14)
        m_pk = DH.gen_public_key()
        mes = 'dh:'+str(m_pk)
        self.socket.send(mes.encode())
        s_pk = self.socket.recv(8192)
        self.shared_key = DH.gen_shared_key(int(s_pk.decode()))
        print('generate share key:\t' + str(self.shared_key))

    """
    取得diffie hellman shared key(不需執行)
    Return:
        shared key
    """

    def get_key(self):
        return self.shared_key


def main():
    """main"""
    try:
        tcpmaster = TcpMaster()

        while True:

            intext = input('please input message: ')

            if intext.startswith('aes:'):
                data = intext[4:]
                print('send aes: ' + data)
                tcpmaster.enc_AES([data])

            elif intext.startswith('pre:'):
                data = intext[4:]
                print('send pre: ' + data)
                tcpmaster.enc_present([data])

            elif intext.startswith('spe:'):
                data = intext[4:]
                print('send spe: ' + data)
                tcpmaster.enc_speck([data])

            elif intext.startswith('sim:'):
                data = intext[4:]
                print('send sim: ' + data)
                tcpmaster.enc_simon([data])

    finally:
        print('server closed connection.')
        tcpmaster.socket.close()


if __name__ == "__main__":
    main()
