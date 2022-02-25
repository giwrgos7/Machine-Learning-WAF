from xml.etree import ElementTree as ET
import urllib.parse 
import base64
import csv

log_path = 'legit_requests'
output_csv_log = 'legit_requests.csv'
class_flag = "legit"

class LogParse:
    def _init_(self):
        pass
    def parse_log(self, log_path):
        result = {}
        try:
            with open(log_path): pass
        except IOError:
            print ("[+] Error!!! ",log_path,"doesn't exist..")
            exit()
        try:
            tree = ET.parse(log_path)
        except Exception:
            print ('[+] Opps..!Please make sure binary data is not present in Log, Like raw image dump,flash(.swf files) dump etc')
            exit()
        root = tree.getroot()
        for reqs in root.findall('item'):
            raw_req = reqs.find('request').text
            raw_req = urllib.parse.unquote(raw_req)
            raw_resp = reqs.find('response').text
            result[raw_req] = raw_resp
        return result

    def parseRawHTTPReq(self, rawreq):
        try:	
            raw = rawreq.decode('utf8')	
        except Exception:	
            raw = rawreq	
        global headers,method,body,path	
        headers = {}	
        sp = raw.split('\r\n\r\n' ,1)	
        if sp[1] != "":	
            head = sp[0]	
            body = sp[1]	
        else :	
            head = sp[0]	
            body = ""	
        c1 = head.split('\n',head.count('\n'))	
        method = c1[0].split(' ',2)[0]	
        path = c1[0].split(' ',2)[1]	
        for i in range(1, head.count('\n')+1):
            slice1 = c1[i].split(': ',1)
            if slice1[0] != "":
                try:
                    headers[slice1[0]] = slice1[1]
                except:
                    pass
        return headers,method,body,path.casefold()

#badwords = ['sleep','drop','uid','select','waitfor','delay','system','union','order by','order','group by','group','concat','admin','having','insert','benchmark','confirm','prompt','alert','find','null','script','and','ontoggle','onmouseover','onpointer','onpointerenter','ontoggleenter','onmouseoverenter']
sql_badwords = ['drop','select','where','from','table','if', 'if (1=1) then', 'if (1=1) select', 'concat', 'char', 'union', 'group by', 'having', 'order by', 'insert', 'exec', 'limit', 'waitfor', 'delay', 'sleep']
xss_badwords = ['script', 'alert', 'prompt', 'eval', 'onclick', 'onerror', 'onpropertychange', 'onresize', 'onload', 'onmouse', 'onblur', 'onkey', 'onfocus', 'fromCharCode', 'ontoggle', 'expression', 'foo']
ci_badwords = ['wget', 'etc', 'passwd', 'cmd', 'cat', 'system', 'bin', 'curl', 'dir', 'echo', 'whoami', 'ifconfig', 'ipconfig', 'netsh', 'netstat', 'net use', 'perl', 'phpinfo', 'reg add', 'print', 'echo']

def ExtractFeatures(method,path_enc,body_enc,headers):
    #badwords_count = 0
    sql_badwords_count = 0
    xss_badwords_count = 0
    ci_badwords_count = 0
    path = urllib.parse.unquote_plus(path_enc)
    body = urllib.parse.unquote(body_enc)
    single_q = path.count("'") + body.count("'")
    double_q = path.count("\"") + body.count("\"")
    dashes = path.count("--") + body.count("--")
    braces = path.count("(") + body.count("(")
    spaces = path.count(" ") + body.count(" ")
    for word in sql_badwords:
        sql_badwords_count += path.count(word) + body.count(word)
    for word in xss_badwords:
        xss_badwords_count += path.count(word) + body.count(word)
    for word in ci_badwords:
        ci_badwords_count += path.count(word) + body.count(word)
    #for header in headers:
        #badwords_count += headers[header].count(word) + headers[header].count(word)
    return [method,path_enc.strip(),body_enc.strip(),single_q,double_q,dashes,braces,spaces,sql_badwords_count,xss_badwords_count,ci_badwords_count,class_flag]
    raw_input('>>>')
   
#Open the log file
f = open(output_csv_log, "w")
c = csv.writer(f)
c.writerow(["method","path","body","single_q","double_q","dashes","braces","spaces","SQL Badwords","XSS Badwords","Command Injection Badords","class"])
f.close()
lp = LogParse()
result = lp.parse_log(log_path)
f = open(output_csv_log, "a")
c = csv.writer(f)
for items in result:
    raw= base64.b64decode(items)
    headers,method,body,path = lp.parseRawHTTPReq(raw)
    result = ExtractFeatures(method,path,body,headers)
    c.writerow(result)
f.close()
