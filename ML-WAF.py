from http.server import SimpleHTTPRequestHandler, HTTPServer
import urllib.parse
from urllib import request, error
import pandas as pd
from pycaret.classification import *
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from requests import Session
import webbrowser
from cgi import parse_header, parse_multipart
from urllib.parse import parse_qs
from socketserver import ThreadingMixIn
from http import client



class CallBackSrv(BaseHTTPRequestHandler):

  protocol_version = 'HTTP/1.1'
  baseurl = 'http://demo.testfire.net'
  session = Session()
  # Open a browser window to our reverse proxy
  webbrowser.open('http://10.100.10.4:80/')

  def do_GET(self):
    resp = self.session.get(self.baseurl + self.path, allow_redirects=True)
    blank = " "
    live_data = ExtractFeatures(self.path,blank)
    result = predict_model(final_et, data = live_data)
    if result['Label'][0] == "SQL Injection":
        print("SQL Injection Detected")
        print("Malicious Request: " + self.path)
        print("Client IP: " + str(self.client_address))
        self.send_error(403, message="Request blocked by ML-WAF")
    elif result['Label'][0] == "XSS":
        print("XSS Attack Detected")
        print("Malicious Request: " + self.path)
        print("Client IP: " + str(self.client_address))
        self.send_error(403, message="Request blocked by ML-WAF")
    elif result['Label'][0] == "command injection":
        print("Command Injection Detected")
        print("Malicious Request: " + self.path)
        print("Client IP: " + str(self.client_address))
        self.send_error(403, message="Request blocked by ML-WAF")
    else:
        self.send_response(resp.status_code)
        self.send_header('Content-Length', len(resp.content))
        self.end_headers()
        self.wfile.write(resp.content)

        
  def parse_POST(self):
    ctype, pdict = parse_header(self.headers['content-type'])
    if ctype == 'multipart/form-data':
      postvars = parse_multipart(self.rfile, pdict)
    elif ctype == 'application/x-www-form-urlencoded':
      length = int(self.headers['content-length'])
      postvars = parse_qs(self.rfile.read(length),
                          keep_blank_values=1)
    else:
      postvars = {}
    return postvars

  def do_POST(self):
    length = int(self.headers.get('content-length'))
    field_data = self.rfile.read(length)
    fields = parse_qs(field_data)
    req_body = urllib.parse.urlencode(fields,doseq=True)
    live_data = ExtractFeatures(self.path,req_body)
    result = predict_model(final_et, data = live_data)
    if result['Label'][0] == "SQL Injection":
        print("SQL Injection Detected")
        print("Malicious Request: " + req_body)
        print("Client IP: " + str(self.client_address))
        self.send_error(403, message="Request blocked by ML-WAF")
    elif result['Label'][0] == "XSS":
        print("XSS Attack Detected")
        print("Malicious Request: " + req_body)
        print("Client IP: " + str(self.client_address))
        self.send_error(403, message="Request blocked by ML-WAF")
    elif result['Label'][0] == "command injection":
        print("Command Injection Detected")
        print("Malicious Request: " + req_body)
        print("Client IP: " + str(self.client_address))
        self.send_error(403, message="Request blocked by ML-WAF")
    else:
        postvars = self.parse_POST()
        resp = self.session.post(self.baseurl + self.path, data=postvars, allow_redirects=True)
        self.send_response(resp.status_code)
        self.send_header('Content-Length', len(resp.content))
        self.end_headers()
        self.wfile.write(resp.content)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
  """ Make our HTTP server multi-threaded """


httpd = ThreadedHTTPServer(('', 80), CallBackSrv)
httpd.serve_forever()