"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""
from http.server import SimpleHTTPRequestHandler

from pocsuite3.api import Output, POCBase, register_poc
from pocsuite3.api import PHTTPServer


class MyRequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        status = 404
        count = 0

        xxe_dtd = '''xxx'''
        if path == "/xxe_dtd":
            count = len(xxe_dtd)
            status = 200
            self.send_response(status)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', '{}'.format(count))
            self.end_headers()
            self.wfile.write(xxe_dtd.encode())
            return
        self.send_response(status)
        self.send_header('Content-Type', 'text/html')
        self.send_header("Content-Length", "{}".format(count))
        self.end_headers()

    def do_HEAD(self):
        status = 404

        if self.path.endswith('jar'):
            status = 200
        self.send_response(status)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", "0")
        self.end_headers()


class DemoPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['seebug']
    vulDate = '2018-03-08'
    createDate = '2018-04-12'
    updateDate = '2018-04-13'
    references = ['']
    name = ''
    appPowerLink = ''
    appName = ''
    appVersion = ''
    vulType = ''
    desc = '''
    '''
    samples = []
    install_requires = ['']

    def _verify(self):
        result = {}
        '''Simple http server demo
           default params:
           		bind_ip='0.0.0.0'
           		bind_port=666
           		is_ipv6=False
           		use_https=False
           		certfile=os.path.join(paths.POCSUITE_DATA_PATH, 'cacert.pem')
                requestHandler=BaseRequestHandler
           You can write your own handler, default list current directory
        '''
        httpd = PHTTPServer(requestHandler=MyRequestHandler)
        httpd.start()

        # Write your code
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    _attack = _verify


register_poc(DemoPOC)