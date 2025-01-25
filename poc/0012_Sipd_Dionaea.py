import socket
from pocsuite3.api import Output, POCBase, register_poc


class DionaeaSipd(POCBase):
    vulID = '0012'
    author = ['jstang']
    name = 'Dionaea Sipd 蜜罐服务'
    project = 'Dionaea'
    appName = 'Sipd'
    appVersion = 'None'
    desc = "Dionaea Sipd 蜜罐服务, 通过Sipd协议使用空数据请求5060端口得到特征值: From:sip:nm@nm;tag=root"

    def _attack(self):
        return self._verify()

    def _verify(self):
        try:
            attr = self.target.split(':')
            if attr[1] != '5060':
                return self.parse_output({})
            # 1.创建套接字
            s = socket.socket()
            # 2.连接
            s.connect((attr[0], int(attr[1])))
            msg = s.recv(1024)
            print('From server: %s' % msg)
            if 'From:sip:nm@nm;tag=root' in str(msg):
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


register_poc(DionaeaSipd)
