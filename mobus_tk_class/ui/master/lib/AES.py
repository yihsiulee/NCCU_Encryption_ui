# -*- coding: UTF-8 -*-
'''
Created on 2019年9月2日
@author: danny
'''
import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class AEAD():
    '''Authenticated encryption with associated data (AEAD)'''
    def __init__(self, aad = '0', key = None, nonce = os.urandom(12)):
        self.key = key
        self.nonce = nonce
        self.aad = aad.encode(encoding='utf-8')
        self.aead = AESGCM(self.key) if key != None else None
        #self.hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        
    
    def _methodinit(self, key = None):
        '''initial for encrypt and decrypt'''
        if key != None:
            self.key = key
        if self.aead == None:
            self.aead = AESGCM(self.key)
    
    
    # encrypt data    
    def encrypt(self, msg, nonce=None, *, key = None):
        self._methodinit(key = key)
        if nonce == None:
            self.NewNonce()
            #return base64.b64encode(self.aead.encrypt(self.nonce, msg.encode(encoding='utf-8'), self.aad)).decode(encoding='utf-8'), base64.b64encode(self.nonce).decode(encoding='utf-8'), base64.b64encode(self.aad).decode(encoding='utf-8')
            return self.aead.encrypt(self.nonce, msg.encode(encoding='utf-8'), self.aad), self.nonce, self.aad

        else:
            return base64.b64encode(self.aead.encrypt(nonce, msg.encode(encoding='utf-8'),self.aad)).decode(encoding='utf-8'), base64.b64encode(self.nonce).decode(encoding='utf-8'), base64.b64encode(self.aad).decode(encoding='utf-8')
        
    
    # decrypt chiper text
    def decrypt(self, ct, nonce=None, aad = '0', *, key = None):
        self._methodinit(key = key)
        if nonce == None:
            return self.aead.decrypt(self.nonce, base64.b64decode(ct), base64.b64decode(aad)).decode(encoding='utf-8')
        else:
            #return self.aead.decrypt(base64.b64decode(nonce.encode(encoding='utf-8')), base64.b64decode(ct), base64.b64decode(aad.encode('utf-8'))).decode(encoding='utf-8')
            return self.aead.decrypt(nonce, ct, aad).decode(encoding='utf-8')

    
    # don't reuse nonce
    def NewNonce(self):
        self.nonce = os.urandom(12)


    def NewKey(self, key):
        self.key = key

            
    def GetKey(self):
        return self.key

    
    def GetNonce(self):
        return self.nonce