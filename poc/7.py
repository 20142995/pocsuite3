import socket
from pocsuite3.api import Output, POCBase, register_poc


class NepenthesFTP(POCBase):
    vulID = '0007'
    author = ['jstang']
    name = 'Nepenthes FTP 蜜罐服务'
    project = 'Nepenthes'
    appName = 'FTP'
    appVersion = 'None'
    desc = "Nepenthes FTP 蜜罐服务, 通过FTP协议使用空数据请求21端口得到特征值: ---freeFTPd 1.0---warFTPd 1.65---\r\n"

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
            msg = s.recv(1024)
            print('From server: %s' % msg)
            if '---freeFTPd 1.0---warFTPd 1.65---' in str(msg):
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


register_poc(NepenthesFTP)
