import socket
from pocsuite3.api import Output, POCBase, register_poc


class DionaeaFtp(POCBase):
    vulID = '0004'
    author = ['jstang']
    name = 'Dionaea FTP 蜜罐服务'
    project = 'Dionaea'
    appName = 'FTP'
    appVersion = 'None'
    desc = "Dionaea FTP 蜜罐服务, 通过FTP协议使用空数据请求21端口得到特征值: 220 Welcome to the ftp service \r\n"

    def _attack(self):
        return self._verify()

    def _verify(self):
        try:
            attr = self.target.split(':')
            if attr[1] != '21':
                return self.parse_output({})
            # 1.创建套接字
            s = socket.socket()
            # 2.连接
            s.connect((attr[0], int(attr[1])))
            # 3.请求
            s.send(b'\\r\\n\\r\\n')  # TCP是面向字节流的协议,在进行TCP通信时都需要转成字节流才可以使用TCP协议进行传输。
            msg = s.recv(1024)
            print('From server: %s' % msg)
            if '220 Welcome to the ftp service' in str(msg):
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


register_poc(DionaeaFtp)
