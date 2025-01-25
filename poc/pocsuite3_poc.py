from collections import OrderedDict
import requests
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, VUL_TYPE


class DemoPOC(POCBase):
    vulID = '97715'  # ssvid
    version = '1.0'
    author = ['kali-team']
    vulDate = '2021-06-01'
    references = ['https://httpbin.org/']
    name = '测试'
    appName = 'thinkphp'
    appVersion = 'thinkphp5.1.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''测试'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    pocDesc = '''测试'''

    def _verify(self):
        result = {}
        response = requests.get(self.url).json()
        if response.get('origin'):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
