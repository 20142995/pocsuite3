import socket
from pocsuite3.api import Output, POCBase, register_poc


class SSHesame(POCBase):
    vulID = '0013'
    author = ['jstang']
    name = 'sshesame SSH 蜜罐服务'
    project = 'sshesame'
    appName = 'SSH'
    appVersion = 'None'
    desc = "sshesame SSH 蜜罐服务, 通过SSH协议使用空数据请求2022端口得到特征值: SSH-2.0-sshesame"

    def _attack(self):
        return self._verify()

    def _verify(self):
        try:
            attr = self.target.split(':')
            if attr[1] != '2022':
                return self.parse_output({})
            # 1.创建套接字
            s = socket.socket()
            # 2.连接
            s.connect((attr[0], int(attr[1])))
            msg = s.recv(1024)
            print('From server: %s' % msg)
            if 'SSH-2.0-sshesame' in str(msg):
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


register_poc(SSHesame)
