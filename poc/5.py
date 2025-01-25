import socket
from pocsuite3.api import Output, POCBase, register_poc


class DionaeaMssql(POCBase):
    vulID = '0005'
    author = ['jstang']
    name = 'Dionaea MSSQL 蜜罐服务'
    project = 'Dionaea'
    appName = 'MSSQL'
    appVersion = 'None'
    desc = r"Dionaea MSSQL 蜜罐服务, 通过MSSQL协议使用空数据请求1443端口得到特征值: \x04\x01\x00\x2b\x00\x00\x00\x00\x00\x00\x1a\x00\x06\x01\x00\x20\x00\x01\x02\x00\x21\x00\x01\x03\x00\x22\x00\x00\x04\x00\x22\x00\x01\xff\x08\x00\x02\x10\x00\x00\x02\x00\x00"

    def _attack(self):
        return self._verify()

    def _verify(self):
        try:
            attr = self.target.split(':')
            if attr[1] != '1443':
                return self.parse_output({})
            # 1.创建套接字
            s = socket.socket()
            # 2.连接
            s.connect((attr[0], int(attr[1])))
            # 3.请求
            s.send(b'\\r\\n\\r\\n')
            msg = s.recv(1024)
            print('From server: %s' % msg)
            if r'\x04\x01\x00\x2b\x00\x00\x00\x00\x00\x00\x1a\x00\x06\x01\x00\x20\x00\x01\x02\x00\x21\x00\x01\x03\x00\x22\x00\x00\x04\x00\x22\x00\x01\xff\x08\x00\x02\x10\x00\x00\x02\x00\x00' in self.bytesToHexString(msg):
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


register_poc(DionaeaMssql)
