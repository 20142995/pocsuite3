# Dionaea 的Memcached协议举例，在实现Memcached协议时Dionaea在一些参数如：version、libevent和rusage_user等都是固定的。
# 仅需IP和端口
import socket
from pocsuite3.api import Output, POCBase, register_poc


class Cowrie(POCBase):
    vulID = '0002'
    author = ['jstang']
    name = "Cowrie Telnet 蜜罐服务"
    project = 'Cowrie'
    appName = 'Telnet'
    appVersion = 'None'
    desc = "Cowrie Telnet 蜜罐服务, 通过TCP使用空数据请求23/2323端口得到特征值: \\xff\\xfd\\x1flogin:"

    def _attack(self):
        return self._verify()

    def _verify(self):
        try:
            attr = self.target.split(':')
            # 0.必须是23/2323端口
            if attr[1] != str(23) and attr[1] != str(2323):
                return self.parse_output({})

            # 1.创建套接字
            s = socket.socket()
            # 2.连接
            s.connect((attr[0], int(attr[1])))
            # 3.校验特征
            msg = s.recv(1024)
            print('From server: %s' % msg)
            if '\\xff\\xfd\\x1flogin:' in str(msg):
                return self.parse_output({'verify': str(msg)})
        except Exception as e:
            print(e)

        return self.parse_output({})

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('The target looks safe!')
        return output


register_poc(Cowrie)
