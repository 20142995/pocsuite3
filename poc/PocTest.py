# -*- coding: utf-8 -*-
from pocsuite3.api import Output
from pocsuite3.api import POCBase
from pocsuite3.api import register_poc
import json
import requests as req
from urllib.parse import urlparse
from requests.packages import urllib3

urllib3.disable_warnings()


class TestPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ["quake"]
    vulDate = '2021-08-04'
    createDate = '2022-06-09'
    updateDate = '2022-06-09'
    references = [""]
    name = "PocTest"
    appPowerLink = ''
    appName = ''
    appVersion = '''
    '''
    vulType = ''

    desc = '''

    '''
    samples = ['']
    install_requires = ['']
    search_keyword = ''

    def _attack(self):
        return self._verify()

    def _verify(self):
        result = {}
        self.raw_url = self.url
        self.host = urlparse(self.url).hostname
        port = urlparse(self.url).port
        scheme = urlparse(self.url).scheme
        if port is None:
            port = "80"
        else:
            port = str(port)
        if "https" == scheme:
            self.url = "%s://%s:%s" % (scheme, self.host, port)
        else:
            self.url = "%s://%s:%s" % (scheme, self.host, port)
        try:
            result['whoami'] = 'root'
            result['ipconfig'] = '''
Windows IP 配置

以太网适配器 Ethernet0:

   连接特定的 DNS 后缀 . . . . . . . : localdomain
   本地链接 IPv6 地址. . . . . . . . : fe80::c586:412a:23d7:6625%12
   IPv4 地址 . . . . . . . . . . . . : 192.168.120.169
   子网掩码  . . . . . . . . . . . . : 255.255.255.0
   默认网关. . . . . . . . . . . . . : 192.168.120.2
           '''
            result['passwd'] = 'ssssss'

        except Exception as e:
            pass

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if len(result.keys()) != 0:
            json_result = {
                "result": {"json": json.dumps(result)}
            }
            output.success(json_result)
        else:
            output.fail('Internet nothing returned')
        return output


register_poc(TestPOC)
