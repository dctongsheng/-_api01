# coding=utf-8
# coding=utf-8
# -*- coding:utf-8 -*-
from datetime import datetime
from wsgiref.handlers import format_date_time
from time import mktime
import hashlib
import base64
import hmac
from urllib.parse import urlencode
import json
import requests
import streamlit as st
import re


class AssembleHeaderException(Exception):
    def __init__(self, msg):
        self.message = msg

class Url:
    def __init__(this, host, path, schema):
        this.host = host
        this.path = path
        this.schema = schema
        pass

class wsParam(object):
    def __init__(self):
        self.APPID = APPID
        self.APIKey = APIKey
        self.APISecret = APISecret
        self.url = 'https://api.xf-yun.com/v1/private/se3acbe7f'
        self.level = level
        self.text = text

    def parse_url(self,requset_url):
        stidx = requset_url.index("://")
        host = requset_url[stidx + 3:]
        schema = requset_url[:stidx + 3]
        edidx = host.index("/")
        if edidx <= 0:
            raise AssembleHeaderException("invalid request url:" + requset_url)
        path = host[edidx:]
        host = host[:edidx]
        u = Url(host, path, schema)
        return u

    def init_header(self):
        headers = {
            'content-type': "application/json",
            'host': 'api.xf-yun.com'
        }
        return headers

    def get_body(self):
        data = {
            "header": {
                "app_id": self.APPID,
                "status": 3,
            },
            "parameter": {
                "se3acbe7f": {
                    "level": self.level,
                    "result": {
                        "encoding": "utf8",
                        "compress": "raw",
                        "format": "json"
                    }
                }
            },
            "payload": {
                "input1": {
                    "encoding": "utf8",
                    "compress": "raw",
                    "format": "plain",
                    "status": 3,
                    "text": str(base64.b64encode(self.text.encode('utf-8')), 'utf-8')
                }
            }
        }
        body = json.dumps(data)
        return body

def assemble_ws_auth_url(requset_url, method="POST", api_key="", api_secret=""):
    u = wsParam.parse_url(requset_url)
    host = u.host
    path = u.path
    now = datetime.now()
    date = format_date_time(mktime(now.timetuple()))
    print(date)
    # date = "Thu, 12 Dec 2019 01:57:27 GMT"
    signature_origin = "host: {}\ndate: {}\n{} {} HTTP/1.1".format(host, date, method, path)
    print("----2",signature_origin)
    signature_sha = hmac.new(api_secret.encode('utf-8'), signature_origin.encode('utf-8'),
                             digestmod=hashlib.sha256).digest()
    signature_sha = base64.b64encode(signature_sha).decode(encoding='utf-8')
    authorization_origin = "api_key=\"%s\", algorithm=\"%s\", headers=\"%s\", signature=\"%s\"" % (
        api_key, "hmac-sha256", "host date request-line", signature_sha)
    print("----1:",authorization_origin)
    authorization = base64.b64encode(authorization_origin.encode('utf-8')).decode(encoding='utf-8')
    print(authorization_origin)
    values = {
        "host": host,
        "date": date,
        "authorization": authorization
    }
    return requset_url + "?" + urlencode(values)

def get_result():
    request_url = assemble_ws_auth_url(wsParam.url, "POST", wsParam.APIKey, wsParam.APISecret)
    print("request_url:", request_url)
    response = requests.post(request_url, data=wsParam.get_body(), headers=wsParam.init_header())
    print("response:", response)
    str_result = response.content.decode('utf8')
    json_result = json.loads(str_result)
    print("response-content:", json_result)
    if json_result. __contains__('header') and json_result['header']['code'] == 0:
        renew_text = json_result['payload']['result']['text']
        print(renew_text)
        # print("\n改写结果：", str(base64.b64decode(renew_text), 'utf-8'))
        f_ttt= str(base64.b64decode(renew_text),'utf-8')
        print(type(f_ttt))
        return f_ttt
    else:
        return ""




if __name__ == "__main__":
    # st.set_page_config(page_title="电竞经理选手招聘辅助工具", page_icon=":rainbow:", layout="wide")
    st.subheader("文本改写助手")
    APPID = "060ac792"
    APISecret = "MWE4OWQxMDEyYzg1MDRiZTgzNjc0Y2Y0"
    APIKey = "62c66266d1aabb1361fc4b1ad19f0b66"
    # level = "<L5>" #改写等级 <L1>  ~  <L6>  等级越高，改写程度越深
    level = st.selectbox(
         '改写等级',
         ['<L1>', '<L2>', '<L3>', '<L4>', '<L5>','<L6>'],help="改写等级 <L1>  ~  <L6>  等级越高，改写程度越深",index=3)
    print(level)
    text = st.text_area(label="请输入文本")
    wsParam = wsParam()
    res = get_result()
    if st.button('改写'):
        try:
            st.write(res.split("[")[2])
        except Exception as e:
            st.write(res)
    else:
        st.write(' ')

    hide_streamlit_style = """
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    </style>

    """
    st.markdown(hide_streamlit_style, unsafe_allow_html=True)
