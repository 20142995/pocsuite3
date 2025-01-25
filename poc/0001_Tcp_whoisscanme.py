import socket
from pocsuite3.api import Output, POCBase, register_poc


class WhoisScanMe(POCBase):
    vulID = '0001'
    author = ['jstang']
    name = 'whoisscanme TCP 蜜罐服务'
    project = 'whoisscanme'
    appName = 'TCP App'
    appVersion = 'None'
    desc = "whoisscanme TCP 蜜罐服务, 通过TCP使用空数据请求任意端口得到特征值: whoisscanme:https://github.com/bg6cq/whoisscanme"

    def _attack(self):
        print(">>>>execute _attack")
        return self._verify()

    def _verify(self):
        try:
            attr = self.target.split(':')
            # 1.创建套接字
            s = socket.socket()
            # 2.连接
            s.connect((attr[0], int(attr[1])))
            # 3.请求
            s.send(b'')  # TCP是面向字节流的协议,在进行TCP通信时都需要转成字节流才可以使用TCP协议进行传输。
            msg = s.recv(1024)
            print('From server: %s' % msg)
            if 'whoisscanme' in str(msg):
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


register_poc(WhoisScanMe)
