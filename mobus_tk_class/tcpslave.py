#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""
 Modbus TestKit: Implementation of Modbus protocol in python
 (C)2009 - Luc Jean - luc.jean@gmail.com
 (C)2009 - Apidev - http://www.apidev.fr
 This is distributed under GNU LGPL license, see license.txt
"""

import sys
from tcpmaster import TcpMaster

import modbus_tk
import modbus_tk.defines as cst
from modbus_tk import modbus_tcp
import pyDH
import time
from speck import SpeckCipher
from simon import SimonCipher

from lib.AES import AEAD
from lib.pypresent import Present
from lib import common


class TcpSlave():

    def __init__(self, slave_id=1, name='0', address=0, length=500):
        self.slave_id = slave_id
        self.name = name
        self.address = address
        self.length = length
        self.DH = pyDH.DiffieHellman(5)
        self.PK = self.DH.gen_public_key()
        self.server = self.init_modbus_slave()

    """
    用AES解密master傳來的資料

    Return: 
        result: 明文
    """

    def dec_AES(self):
        aead = AEAD()
        slave = self.server.get_slave(self.slave_id)
        values = slave.get_values(self.name, self.address, self.length)
        print("receive values is       " + str(values))
        tmp_nones = self.server.get_slave(3).get_values('nonce', 0, 500)
        cts = common.combine(values, 0, tmp_nones[0])
        nones = common.combine(tmp_nones, 1, tmp_nones[0])
        result = []
        start_time = time.time()
        for i in range(tmp_nones[0]):
            result.append(aead.decrypt(cts[i].to_bytes(17, sys.byteorder), nones[i].to_bytes(12, sys.byteorder),
                                       b'0', key=bytes.fromhex(share)))
        end_time = time.time()
        print("after decrypt value is  " + str(result))
        print("decrypt time is  " + str(end_time - start_time))
        return str(result)

    """
    用present解密master傳來的資料

    Return: 
        result: 明文
    """

    def dec_present(self):
        slave = self.server.get_slave(self.slave_id)
        values = slave.get_values(self.name, self.address, self.length)
        print("receive values is       " + str(values))
        tmp_nones = self.server.get_slave(3).get_values('nonce', 0, 500)
        cts = common.combine(values, 0, tmp_nones[0])
        result = []
        key = bytes.fromhex(share)[:10]
        cipher = Present(key)
        start_time = time.time()
        for i in range(tmp_nones[0]):
            result.append(
                int.from_bytes(
                    cipher.decrypt(
                        cts[i].to_bytes(8, byteorder="big")
                    ),  "big"
                )
            )
        end_time = time.time()
        print("after decrypt value is  " + str(result))
        print("decrypt time is  " + str(end_time - start_time))
        return str(result)

    """
    用speck解密master傳來的資料

    Return: 
        result: 明文
    """

    def dec_speck(self):
        slave = self.server.get_slave(self.slave_id)
        values = slave.get_values(self.name, self.address, self.length)
        print("receive values is       " + str(values))
        tmp_nones = self.server.get_slave(3).get_values('nonce', 0, 500)
        cts = common.combine(values, 0, tmp_nones[0])
        result = []
        key = int(share, 16)
        cipher = SpeckCipher(key)
        start_time = time.time()
        for i in range(tmp_nones[0]):
            result.append(cipher.decrypt(cts[i]))
        end_time = time.time()
        print("after decrypt value is  " + str(result))
        print("decrypt time is  " + str(end_time - start_time))
        return str(result)

    """
    用simon解密master傳來的資料

    Return: 
        result: 明文
    """

    def dec_simon(self):
        slave = self.server.get_slave(self.slave_id)
        values = slave.get_values(self.name, self.address, self.length)
        print("receive values is       " + str(values))
        tmp_nones = self.server.get_slave(3).get_values('nonce', 0, 500)
        cts = common.combine(values, 0, tmp_nones[0])
        result = []
        key = int(share, 16)
        cipher = SimonCipher(key)
        start_time = time.time()
        for i in range(tmp_nones[0]):
            result.append(cipher.decrypt(cts[i]))
        end_time = time.time()
        print("after decrypt value is  " + str(result))
        print("decrypt time is  " + str(end_time - start_time))
        return str(result)

    """
    初始modbus_slave設定
    Return:
        server: instance of modbus slave
    """

    def init_modbus_slave(self):
        server = modbus_tcp.TcpServer()
        server.start()
        slave_1 = server.add_slave(1)
        slave_1.add_block('0', cst.HOLDING_REGISTERS, 0, 500)
        slave_2 = server.add_slave(2)
        slave_2.add_block('DH_PK', cst.HOLDING_REGISTERS, 0, 800)
        sp_num = common.split_num(self.PK, 4)
        slave_2.set_values('DH_PK', 0, [int(s)
                           for s in sp_num] + [len(sp_num[-1])])
        server.add_slave(3).add_block('nonce', cst.HOLDING_REGISTERS, 0, 500)
        return server

    """
    取得diffie hellman shared key(需先執行才加密，先執行master再執行slave)
    Return:
        share: shared key
    """

    def get_key(self):
        global share
        values = [str(num)
                  for num in self.server.get_slave(1).get_values('0', 0, 117)]
        m_pk = common.merge_num(values[:-2])
        m_pk += values[-2].rjust(int(values[-1]), '0')
        share = self.DH.gen_shared_key(int(m_pk))
        print('generate share key:\t' + str(share))
        return share


def main():
    """main"""
    # DH public ley
    DH = pyDH.DiffieHellman(5)
    PK = DH.gen_public_key()
    global share
    logger = modbus_tk.utils.create_logger(
        name="console", record_format="%(message)s")
    aead = AEAD()

    try:
        tcpslave = TcpSlave()
        # Create the server
        logger.info("running...")
        logger.info("enter 'quit' for closing the server")
        logger.info("enter 'add_slave [id]' to add a new server with id")
        logger.info("enter 'add_block [id] [block_name] [block_type] [starting_address] [length]' to add a block, where block_type is describe as following:\n\t COILS = 1 DISCRETE_INPUTS = 2 HOLDING_REGISTERS = 3 ANALOG_INPUTS = 4")
        logger.info(
            "enter 'set_values [id] [block_name] [address] [bit_values ...]' to add multi value in the block")
        logger.info(
            "enter 'get_values [id] [block_name] [address] [length]' to add multi value in the block")

        while True:
            try:
                cmd = sys.stdin.readline()
                args = cmd.split()

                if cmd.find('quit') == 0:
                    sys.stdout.write('bye-bye\r\n')
                    break

                # elif args[0] == 'add_slave':
                #     slave_id = int(args[1])
                #     server.add_slave(slave_id)
                #     sys.stdout.write('done: slave %d added\r\n' % slave_id)

                # elif args[0] == 'add_block':
                #     slave_id = int(args[1])
                #     name = args[2]
                #     block_type = int(args[3])
                #     starting_address = int(args[4])
                #     length = int(args[5])
                #     slave = server.get_slave(slave_id)
                #     slave.add_block(name, block_type, starting_address, length)
                #     sys.stdout.write('done: block %s added\r\n' % name)

                # elif args[0] == 'set_values':
                #     slave_id = int(args[1])
                #     name = args[2]
                #     address = int(args[3])
                #     values = []
                #     for val in args[4:]:
                #         values.append(int(val))
                #     slave = server.get_slave(slave_id)
                #     slave.set_values(name, address, values)
                #     values = slave.get_values(name, address, len(values))
                #     sys.stdout.write('done: values written: %s\r\n' % str(values))

                elif args[0] == 'get_present_values':
                    result = tcpslave.dec_present()
                    print(result)

                elif args[0] == 'get_speck_values':
                    result = tcpslave.dec_speck()
                    print(result)

                elif args[0] == 'get_simon_values':
                    result = tcpslave.dec_simon()
                    print(result)

                elif args[0] == 'get_values':
                    result = tcpslave.dec_AES()
                    print(result)

                elif args[0] == 'get_dh':
                    tcpslave.get_key()

                else:
                    sys.stdout.write("unknown command %s\r\n" % args[0])
            except Exception as e:
                logger.error(e)
    finally:
        print()


if __name__ == "__main__":
    main()
