#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""
 Modbus TestKit: Implementation of Modbus protocol in python
 (C)2009 - Luc Jean - luc.jean@gmail.com
 (C)2009 - Apidev - http://www.apidev.fr
 This is distributed under GNU LGPL license, see license.txt
"""

from __future__ import print_function

import modbus_tk
import modbus_tk.defines as cst
from modbus_tk import modbus_tcp, hooks
import pyDH
import logging
import sys
import time
from speck import SpeckCipher
from simon import SimonCipher

from lib.AES import AEAD
from lib.pypresent import Present
from lib import common


class TcpMaster():

    def __init__(self, slave_id=1, cmd_type=16, address=0):
        self.slave_id = slave_id
        self.cmd_type = cmd_type
        self.address = address
        self.master = self.init_modbus_master()

    """
    用AES加密
    Args:
        values:list of values ex."[5,7]"
    Return:
        cts:密文
    """

    def enc_AES(self, values):
        aead = AEAD()
        cts = []
        print("origin values is       " + str(values))
        start = 1
        self.master.execute(3, self.cmd_type, 0, output_value=[len(values)])
        start_time = time.time_ns()
        for i in range(len(values)):
            key = bytes.fromhex(share)
            ct, nonce, aad = aead.encrypt(values[i], key=key)
            tmp_nonce = str(int.from_bytes(nonce, sys.byteorder))
            self.master.execute(3, self.cmd_type, start, output_value=[
                                len(tmp_nonce)]+[int(n) for n in tmp_nonce])
            start += (len(tmp_nonce) + 1)
            ct = str(int.from_bytes(ct, sys.byteorder))
            ct = [int(n) for n in ct]
            '''
            store_key.insert(i, {
                'ct': ct,
                'nonce': nonce,
                'aad': aad,
                'key': key,
                'length': len(ct)
            })
            '''
            cts.extend([len(ct)] + ct)
        end_time = time.time_ns()
        print("after encrypt value is " + str(cts))
        print("encrypt time is " + str(end_time - start_time) + " nanoseconds.")
        return cts

    """
    用present加密
    Args:
        values:list of values ex."[5,7]"
    Return:
        cts:密文
    """

    def enc_present(self, values):
        cts = []
        print("origin values is       " + str(values))
        self.master.execute(3, self.cmd_type, 0, output_value=[len(values)])
        key = bytes.fromhex(share)[:10]
        cipher = Present(key)
        start_time = time.time_ns()
        for i in range(len(values)):
            encrypted = cipher.encrypt(bytes([int(values[i])]))
            ct = str(int.from_bytes(encrypted, "big"))
            ct = [int(n) for n in ct]
            cts.extend([len(ct)] + ct)
        end_time = time.time_ns()
        print("after encrypt value is " + str(cts))
        print("encrypt time is " + str(end_time - start_time) + " nanoseconds.")
        # print(master.execute(slave_id, cmd_type, address, output_value=cts))
        return cts

    """
    用speck加密
    Args:
        values:list of values ex."[5,7]"
    Return:
        cts:密文
    """

    def enc_speck(self, values):
        cts = []
        print("origin values is       " + str(values))
        self.master.execute(3, self.cmd_type, 0, output_value=[len(values)])
        key = int(share, 16)
        cipher = SpeckCipher(key)
        start_time = time.time_ns()
        for i in range(len(values)):
            encrypted = cipher.encrypt(int(values[i]))
            ct = str(encrypted)
            ct = [int(n) for n in ct]
            cts.extend([len(ct)] + ct)
        end_time = time.time_ns()
        print("after encrypt value is " + str(cts))
        print("encrypt time is " + str(end_time - start_time) + " nanoseconds.")
        #print(master.execute(slave_id, cmd_type, address, output_value=cts))
        return cts

    """
    用simon加密
    Args:
        values:list of values ex."[5,7]"
    Return:
        cts:密文
    """

    def enc_simon(self, values):
        cts = []
        print("origin values is       " + str(values))
        self.master.execute(3, self.cmd_type, 0, output_value=[len(values)])
        key = int(share, 16)
        cipher = SimonCipher(key)
        start_time = time.time_ns()
        for i in range(len(values)):
            encrypted = cipher.encrypt(int(values[i]))
            ct = str(encrypted)
            ct = [int(n) for n in ct]
            cts.extend([len(ct)] + ct)
        end_time = time.time_ns()
        print("after encrypt value is " + str(cts))
        print("encrypt time is " + str(end_time - start_time) + " nanoseconds.")
        #print(master.execute(slave_id, cmd_type, address, output_value=cts))
        return cts

    """
    初始modbus_master設定
    Return:
        master: instance of modbus master
    """

    def init_modbus_master(self):
        logger = modbus_tk.utils.create_logger("console", level=logging.DEBUG)

        def on_after_recv_ini(data):
            bytes_data = data
            logger.info(bytes_data)

        hooks.install_hook('modbus.Master.after_recv', on_after_recv_ini)

        def on_before_connect(args):
            master = args[0]
            logger.debug("on_before_connect {0} {1}".format(
                master._host, master._port))

        hooks.install_hook(
            "modbus_tcp.TcpMaster.before_connect", on_before_connect)

        def on_after_recv(args):
            response = args[1]
            logger.debug(
                "on_after_recv {0} bytes received".format(len(response)))

        hooks.install_hook("modbus_tcp.TcpMaster.after_recv", on_after_recv)

        # Connect to the slave
        master = modbus_tcp.TcpMaster()
        master.set_timeout(5.0)
        logger.info("connected")

        logger.info(master.execute(1, cst.READ_HOLDING_REGISTERS, 0, 3))

        return master

    """
    傳送資料給slave
    Args:
        values: 欲傳送的資料
    """

    def send_to_slave(self, values, slave_id=1, cmd_type=16, address=0):
        self.master.execute(slave_id, cmd_type, address, output_value=values)

    """
    取得diffie hellman shared key(需先執行才加密，先執行master再執行slave)
    Return:
        share: shared key
    """

    def get_key(self):
        global share
        DH = pyDH.DiffieHellman(5)
        PK = DH.gen_public_key()
        values = [str(num) for num in self.master.execute(2, 3, 0, 117)]
        print("receive public key is       " + str(values))
        s_pk = common.merge_num(values[:-2])
        s_pk += values[-2].rjust(int(values[-1]), '0')
        share = DH.gen_shared_key(int(s_pk))

        sp_num = common.split_num(PK, 4)
        self.master.execute(1, 16, 0, output_value=[
                            int(s) for s in sp_num] + [len(sp_num[-1])])

        print('generate share key:\t' + str(share))
        return share


def main():
    """main"""
    tcpmaster = TcpMaster()

    while True:
        try:
            cmd = sys.stdin.readline()
            args = cmd.split()

            if cmd.find('quit') == 0:
                sys.stdout.write('bye-bye\r\n')
                break

            elif args[0] == 'set_values':
                cts = tcpmaster.enc_AES([str(i) for i in args[1:]])
                tcpmaster.send_to_slave(cts)

            elif args[0] == 'set_present_values':
                cts = tcpmaster.enc_present([str(i) for i in args[1:]])
                tcpmaster.send_to_slave(cts)

            elif args[0] == 'set_speck_values':
                cts = tcpmaster.enc_speck([str(i) for i in args[1:]])
                tcpmaster.send_to_slave(cts)

            elif args[0] == 'set_simon_values':
                cts = tcpmaster.enc_simon([str(i) for i in args[1:]])
                tcpmaster.send_to_slave(cts)

            elif args[0] == 'get_dh':
                tcpmaster.get_key()

            else:
                sys.stdout.write("unknown command %s\r\n" % args[0])

        except Exception as e:
            print(e)


if __name__ == "__main__":
    main()
