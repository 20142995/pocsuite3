import socket
from pocsuite3.api import Output, POCBase, register_poc


class ConpotModbus(POCBase):
    vulID = '0010'
    author = ['jstang']
    name = 'Conpot Modbus 蜜罐服务'
    project = 'Conpot'
    appName = 'Modbus'
    appVersion = 'None'
    desc = "Conpot Modbus 蜜罐服务, 通过Modbus协议使用空数据请求502端口得到特征值: Device Identification: Siemems SIMATIC S7-200"

    def _attack(self):
        return self._verify()

    def _verify(self):
        try:
            attr = self.target.split(':')
            if attr[1] != '502':
                return self.parse_output({})
            # 1.创建套接字
            s = socket.socket()
            # 2.连接
            s.connect((attr[0], int(attr[1])))
            msg = s.recv(1024)
            print('From server: %s' % msg)
            if 'Device Identification: Siemems SIMATIC S7-200' in str(msg):
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


register_poc(ConpotModbus)
