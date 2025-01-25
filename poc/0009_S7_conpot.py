import socket
from pocsuite3.api import Output, POCBase, register_poc


class S7Conpot(POCBase):
    vulID = '0009'
    author = ['jstang']
    name = 'Conpot S7 蜜罐服务'
    project = 'Conpot'
    appName = 'S7'
    appVersion = 'None'
    desc = "Conpot S7 蜜罐服务, 通过S7协议使用空数据请求102端口得到特征值: Serial number of module: 88111222"

    def _attack(self):
        return self._verify()

    def _verify(self):
        try:
            attr = self.target.split(':')
            if attr[1] != '102':
                return self.parse_output({})
            # 1.创建套接字
            s = socket.socket()
            # 2.连接
            s.connect((attr[0], int(attr[1])))
            msg = s.recv(1024)
            print('From server: %s' % msg)
            if 'Serial number of module:8811122' in str(msg):
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


register_poc(S7Conpot)
