# Dionaea 的Memcached协议举例，在实现Memcached协议时Dionaea在一些参数如：version、libevent和rusage_user等都是固定的。
# 仅需IP和端口
import socket
from pocsuite3.api import Output, POCBase, register_poc


class Amun(POCBase):
    vulID = '0003'
    author = ['jstang']
    name = "Amun IMAP 蜜罐服务"
    project = 'Amun'
    appName = 'IMAP'
    appVersion = 'None'
    desc = "Amun IMAP 蜜罐服务, 通过imap协议使用数据(\\r\\n\\r\\n)请求143端口得到特征值: a001 OK LOGIN completed"

    def _attack(self):
        return self._verify()

    def _verify(self):
        try:
            attr = self.target.split(':')
            if attr[1] != str(143):
                return self.parse_output({})
            # 1.创建套接字
            s = socket.socket()
            # 2.连接
            s.connect((attr[0], int(attr[1])))
            # 3.请求
            s.send(b'\r\n\r\n')  # TCP是面向字节流的协议,在进行TCP通信时都需要转成字节流才可以使用TCP协议进行传输。
            msg = s.recv(1024)
            print('From server: %s' % msg)
            if 'a001' in str(msg) and 'OK' in str(msg) and 'LOGIN' in str(msg) and 'completed' in str(msg):
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


register_poc(Amun)
