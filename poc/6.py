import socket
from pocsuite3.api import Output, POCBase, register_poc


class KojoneySSH(POCBase):
    vulID = '0006'
    author = ['jstang']
    name = 'Kojoney SSH 蜜罐服务'
    project = 'Kojoney'
    appName = 'SSH'
    appVersion = 'None'
    desc = "Kojoney SSH 蜜罐服务, 通过imap协议使用空数据请求22/2222端口得到特征值: SSH-2.0-Twisted\\r\\n"

    def _attack(self):
        return self._verify()

    def _verify(self):
        try:
            attr = self.target.split(':')
            if attr[1] != '22' and attr[1] != '2222':
                return self.parse_output({})
            # 1.创建套接字
            s = socket.socket()
            # 2.连接
            s.connect((attr[0], int(attr[1])))
            msg = s.recv(1024)
            print('From server: %s' % msg)
            if 'SSH-2.0-Twisted' in str(msg):
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


register_poc(KojoneySSH)
