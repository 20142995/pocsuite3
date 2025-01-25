import socket
from pocsuite3.api import Output, POCBase, register_poc


class NepenthesNetbios(POCBase):
    vulID = '0008'
    author = ['jstang']
    name = 'Nepenthes NETBIOS 蜜罐服务'
    project = 'Nepenthes'
    appName = 'NETBIOS'
    appVersion = 'None'
    desc = "Nepenthes NETBIOS 蜜罐服务, 通过NETBIOS协议使用空数据请求2103端口得到特征值: \x82\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    def _attack(self):
        return self._verify()

    def _verify(self):
        try:
            attr = self.target.split(':')
            if attr[1] != '2103':
                return self.parse_output({})
            # 1.创建套接字
            s = socket.socket()
            # 2.连接
            s.connect((attr[0], int(attr[1])))
            msg = s.recv(1024)
            print('From server: %s' % msg)
            if r'\x82\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' in self.bytesToHexString(msg):
                return self.parse_output({'verify': self.bytesToHexString(msg)})
        except Exception as e:
            print(e)

        return self.parse_output({})

    def bytesToHexString(self, bs: bytes):
        # hex_str = ''
        # for item in bs:
        #     hex_str += str(hex(item))[2:].zfill(2).upper() + " "
        # return hex_str
        return ''.join(['\\x%02x' % b for b in bs])

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('The target looks safe!')
        return output


register_poc(NepenthesNetbios)
