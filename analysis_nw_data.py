# _*_ coding:utf-8 _*_

"""
-------------------------------------------------
@Author: dearest
@Data: 2022/11/18 11:32
@File: analysis_nw_data.py
@Version: 1.0.0
@Description: TODO
@Question: 怎么消除误报？？？
-------------------------------------------------
"""
import base64
import hmac
import ipaddress
import json
import os
import sqlite3
import time
import datetime
from hashlib import sha256

import numpy as np
import pandas as pd
import requests
import redis
import config  # 自定义的配置文件config.py
import warnings

warnings.filterwarnings('ignore')


def _json(A=None, **B):
    """
    @description: 辅助方法，字典转json
    :param A: 解决url中的请求参数问题，get/post请求的时候，通常请求体会写成字典的形式或不符合json的规范
    :param B: B参数是可以传入任意键值对的形式进行json规范，A为None，也是为了能够传任意的键值对，类似 key=value
    :returns:  传入字典类型或键值对，都返回json的格式
    """
    if isinstance(A, dict):
        return json.dumps(A, separators=(',', ':'), ensure_ascii=False)
    else:
        return json.dumps(B, separators=(',', ':'), ensure_ascii=False)


class REDIS:
    host = config.redis_host
    port = config.redis_port
    password = config.redis_password

    def __init__(self, host=host, port=port, password=password):
        try:
            pool = redis.ConnectionPool(host=host, port=port, password=password)
            self.conn = redis.Redis(connection_pool=pool)
        except Exception:
            msg = "0x03 === redis连接错误！检查redis进程是否正常运行！"
            Feishu(msg).payload1()
            print(msg)

    def __del__(self):
        """程序结束，关闭连接池，释放资源"""
        self.conn.connection_pool.disconnect()


class CONN_CS:
    """
    @description: 定义csp 的ip、session、headers 以及待访问的url
    @className: CONN_CS
    @methodName: url_type()返回待访问的http请求链接
    """

    def __init__(self, ip, cookie):
        self.dev_ip = ip
        self.dev_cookie = cookie
        self.req_header = {"Content-Type": "application/json;charset=utf-8", "Cookie": self.dev_cookie, }

    def url_type(self, url, *args):
        """
        @description:
        :param url: 通过传参数，返回对应的http链接
        :param args: 主要是为了扩展"事件详情"页面的请求参数
        :return:返回一个http链接字符串
        """
        if url == 0:  # 特征检测url  post
            return "http://" + self.dev_ip + "/api/netidsEventlog/page"
        if url == 1:  # 事件详情url  get
            return "http://" + self.dev_ip + "/api/netidsEventlog/detail/old/" + args[0] + "/" + args[1].replace(" ",
                                                                                                                 "%20")
        if url == 2:  # 监测cs是否运行正常的url get
            return "http://" + self.dev_ip + "/api/eventLogQueryParam/listCurrentUser"


def request_param(beginTime, endTime, pageSize, **kwargs) -> str:
    """
    @description: 定义请求特征页面时的请求体；可通过**kwargs扩展
    :param beginTime: 请求cs日志开始时间
    :param endTime: 请求cs日志结束时间
    :param pageSize: 每次获取的日志条数
    :return: 返回json格式
    """
    # eventName:str
    # srcip6s:list
    # dstip6s:list
    param_dict = {"datasourceType": "old", "oldDatasourceType": "self",
                  "displayColumns": {"srcport": 1, "dstport": 1, "eventtypeid": 1, "eventlevel": 1, "eventtime": 1,
                                     "securityid": 1, "attackid": 1, "srcipStr": 1, "dstipStr": 1, "attackResult": 1},
                  "queryParam": {"startTime": beginTime, "endTime": endTime},
                  "page": {"pageNo": 1, "pageSize": pageSize},
                  "orderBy": {"field": "EVENTTIME", "order": -1}}

    param_dict['queryParam'].update(kwargs)
    return json.dumps(param_dict, separators=(',', ':'))


def func1(A):
    """
    :param A : 传入一个列表
    1、先对源、目的、事件不再黑白名单的IP进行去重
    2、返回一个可疑的源IP列表
    """
    B = np.array(A)
    C = []
    for element in B.flat:
        srcIp = element['srcipStr']
        destIp = element['dstipStr']
        eventName = element['eventName']

        # 事件名称在黑名单，则开始分析
        if eventName in config.eventName_black_list:
            C.append(srcIp)
        # 事件名称在白名单，则pass
        elif eventName in config.eventName_white_list:
            pass
        # 源IP或目的IP有一个在白名单，则pass
        elif srcIp in config.source_ip_white_list:
            pass
        elif destIp in config.destination_ip_white_list:
            pass
        # 源IP或目的IP在一个在黑名单，则开始分析
        elif srcIp in config.source_ip_black_list or destIp in config.destination_ip_black_list:
            C.append(srcIp)
        # 以上条件都不符合，则开始分析
        else:
            C.append(srcIp)

    # 将numpy.ndarray转list
    tmp = list(set(C))
    func2(tmp)
    # func2(np.unique(C).tolist())


def func2(A):
    # 源IP对应的近30天所有数据
    req_startTime1 = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y-%m-%d 23:00:00')
    req_endTime1 = req_endTime

    # print(f"S1/{req_startTime1}, E1/{req_endTime1}")
    B = request_param(beginTime=req_startTime1, endTime=req_endTime1, pageSize=1000000, srcip6s=A)

    C = request_server(B)
    D = np.array(C)
    # print(D.shape)
    E = []
    for element in D.flat:
        eventTime = element['eventTimeStr']
        eventName = element['eventName']
        srcIp = element['srcipStr']
        destIp = element['dstipStr']
        srcPort = element['srcport']
        destPort = element['dstport']
        eventLevel = element['eventlevel']

        E.append([eventName, srcIp, destIp, srcPort, destPort, eventLevel, eventTime, 0])
    F = np.array(E)
    # print(F.shape)
    print(f"监控到攻击IP的当天的所有的日志 {F.shape[0]} 条，正在处理...")
    # 分组去重排序后的列：b h a c d e f g  对应： 源IP 计数 事件名 目的IP 源端口 目的端口 事件等级 时间
    df = pd.DataFrame(F, columns=["a", "b", "c", "d", "e", "f", "g", "h"])

    """
    # 主要为了兼容windows中莫名其妙的BUG才写的！！！
    new_df = df.groupby(["b", "c"])
    a1 = new_df['a'].unique()
    b1 = new_df['d'].unique()
    c1 = new_df['e'].unique()
    d1 = new_df['f'].unique()
    e1 = new_df['g'].apply(lambda x: np.sort(x))
    f1 = new_df['h'].count()
    new_df1 = pd.concat([a1, b1, c1, d1, e1, f1], axis=1, ignore_index=False)
    """
    new_df1 = df.groupby(["b", "c"]).agg(
        {"a": np.unique, "d": np.unique, "e": np.unique, "f": np.unique, "g": np.sort, "h": "count"})
    G = np.array(new_df1.to_records())
    # 建立redis连接
    rr = REDIS().conn
    xlsx_data1 = []  # 告警事件的xlsx表格
    xlsx_data2 = []  # 误报事件的xlsx表格
    for element in G.flat:

        srcIp = element[0]
        destIp = element[1]
        eventName = element[2]
        srcPort = element[3]
        destPort = element[4]
        eventLevel = element[5]
        eventTime = element[6]
        count = element[7]
        H = func3(srcIp, count, eventName, destIp, srcPort, destPort, eventLevel, eventTime, rr)
        key = f"{srcIp}_{destIp}"
        name = "events" + (datetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y%m%d')

        if H:
            if rr.hexists(name=name, key=key):
                res = json.loads(REDIS().conn.hget(name=name, key=key).decode())
                # 时间 30天第一次事件发生的时间 源IP 源IP归属 目的IP 目的IP归属 今天的所有事件 30天的源IP对目的IP的所有事件 30天内事件发生的所有次数
                result = [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), res['first30'], srcIp, query_ip(srcIp),
                          destIp, query_ip(destIp), eventName, res['eventName'], str(count) + res['count'], str(count)]
                # print(srcIp, destIp, destPort, srcPort)
                xlsx_data1.append(result)

            else:
                result = [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), eventTime[0], srcIp, query_ip(srcIp),
                          destIp, query_ip(destIp), eventName, eventName, str(count), str(count)]
                # print(srcIp, destIp, destPort, srcPort)
                xlsx_data1.append(result)
        else:
            if rr.hexists(name=name, key=key):
                res = json.loads(REDIS().conn.hget(name=name, key=key).decode())

                # 当前时间 源ip 源ip归属 目的ip 目的ip归属 事件 30天内第一次攻击的时间 次数
                result = [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), srcIp, query_ip(srcIp), destIp,
                          query_ip(destIp), eventName, res['first30'], str(count) + res['count'], str(count)]
                # print(srcIp, destIp, destPort, srcPort)
                xlsx_data2.append(result)
            else:
                result = [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), srcIp, query_ip(srcIp), destIp,
                          query_ip(destIp), eventName, eventTime[0], str(count), str(count)]
                # print(srcIp, destIp, destPort, srcPort)
                xlsx_data2.append(result)
    rr.__del__()  # 释放资源
    if len(xlsx_data1) > 0 or len(xlsx_data2) > 0:
        # Feishu(xlsx_data1).payload2()
        func4(xlsx_data1)
        func5(xlsx_data2)
    else:
        print("没要要写入表格中的内容!没有要发送的数据！")


def func3(srcIp, count, eventName, destIp, srcPort, destPort, eventLevel, eventTime, rr) -> bool:
    """
    1、返回bool值，True 为真的攻击，False为误报
    2、可自定义误报的特征
    """
    low_event = ["HTTP_SQL错误信息泄露_2", "ICMP_分布式拒绝服务_TFN_客户命令", "TCP_远程控制软件_Radmin_远程控制",
                 "TCP_MS_RDP远程桌面_建立低安全性连接",
                 "DOS_UDP_FLOOD_拒绝服务", "HTTP_url躲避", "HTTP_XSS疑似注入", "SCAN_UDP端口扫描"]

    if len(eventName) == 1 and count <= 5 and query_ip(destIp) == "非内网IP":
        return False
    elif len(eventName) == 1 and eventName[0] in low_event and count <= 5:
        return False
    elif len(eventName) == 1:
        key = f"{srcIp}_{destIp}"
        if rr.hexists("rule1", key=key):
            res = json.loads(REDIS().conn.hget("rule1", key).decode())
            # print(res)
            if eventName[0] in res['eventName']:
                var1 = []
                var2 = []
                [var1.clear() if _ in res['srcPort'] else var1.append(_) if "*" not in res['srcPort'] else var1.clear()
                 for _ in srcPort]
                [var2.clear() if _ in res['destPort'] else var2.append(_) if "*" not in res[
                    'destPort'] else var2.clear() for _ in destPort]
                if len(var1) == 0 and len(var2) == 0:
                    return False
                else:
                    return True
            else:
                return True
        else:
            return True
    elif len(eventName) > 1:
        key = f"{srcIp}_{destIp}"
        if rr.hexists("rule2", key=key):
            res = json.loads(REDIS().conn.hget("rule2", key).decode())
            var1 = []  # srcPort
            var2 = []  # destPort
            var3 = []  # eventName
            for _ in eventName:
                if _ in res['eventName']:
                    [var1.clear() if _1 in res['srcPort'] else var1.append(_1) if "*" not in res[
                        'srcPort'] else var1.clear() for _1 in res['srcPort']]

                    [var2.clear() if _2 in res['destPort'] else var2.append(_2) if "*" not in res[
                        'destPort'] else var2.clear() for _2 in res['destPort']]
                else:
                    var3.append(_)
            if len(var1) == 0 and len(var2) == 0 and len(var3) == 0:
                return False
            else:
                return True
        else:
            return True


def func4(A):
    # xlsx ： 时间 30天第一次事件发生的时间 源IP 源IP归属 目的IP 目的IP归属 今天的所有事件 30天的源IP对目的IP的所有事件 30天内事件发生的所有次数 今天出现的次数(昨天23:30到现在)
    folder = os.getcwd() + '/excel_event/'
    path = os.listdir(folder)
    xlsx_name = "event_" + time.strftime("%Y_%m_%d") + ".xlsx"
    field = ['当前时间', '30天内第一次事件发生的时间', '源IP', '源归属', '目的IP', '目的归属', '今天的所有事件',
             '30天的源IP对目的IP的所有事件', '30天内事件发生的所有次数', '今天出现的次数(昨天23:00到现在)']
    if xlsx_name not in path:
        data = pd.DataFrame(A, columns=field)
        write = pd.ExcelWriter(folder + xlsx_name)
        data.to_excel(write, index=False)
        write.save()
    else:
        original_data = pd.read_excel(folder + xlsx_name)  # 表格中的原始数据
        append_data = pd.DataFrame(A, columns=field)  # 待追加的数据
        # now_data = original_data.append(append_data)  # 合并数据
        now_data = pd.concat([original_data, append_data])
        now_data.to_excel(folder + xlsx_name, index=False)


def func5(A):
    # xlsx ：当前时间 源ip 源ip归属 目的ip 目的ip归属 今天的所有事件 30天内第一次攻击的时间 次数 今天出现的次数(昨天23:30到现在)
    folder = os.getcwd() + '/excel_wu_bao/'
    path = os.listdir(folder)
    xlsx_name = "WuBao_" + time.strftime("%Y_%m_%d") + ".xlsx"
    field = ['当前时间', '源IP', '源归属', '目的IP', '目的归属', '今天的所有事件', '30天内事件第一次出现的时间',
             '30天内事件发生的所有次数', '今天出现的次数(昨天23:00到现在)']
    if xlsx_name not in path:
        data = pd.DataFrame(A, columns=field)
        write = pd.ExcelWriter(folder + xlsx_name)
        data.to_excel(write, index=False)
        write.save()
    else:
        original_data = pd.read_excel(folder + xlsx_name)  # 表格中的原始数据
        append_data = pd.DataFrame(A, columns=field)  # 待追加的数据
        # now_data = original_data.append(append_data)  # 合并数据
        now_data = pd.concat([original_data, append_data])
        now_data.to_excel(folder + xlsx_name, index=False)


def query_ip(ip) -> str:
    try:
        if ipaddress.ip_address(ip).version == 4:
            conn = sqlite3.connect(config.sqlite_position)
            c = conn.cursor()
            c.execute(f"select name from assert where ip = '{ip}'")
            res = c.fetchone()
            if res:
                return res[0]
            else:
                var = ip.split('.')
                var1 = str(var[0]) + '.' + str(var[1]) + '.' + str(var[2]) + '.'
                var2 = str(var[0]) + '.' + str(var[1]) + '.'
                var3 = str(var[0]) + '.'
                if var1 in config.assert_dict:
                    return config.assert_dict[var1]
                elif var2 in config.assert_dict:
                    return config.assert_dict[var2]
                elif var3 in config.assert_dict:
                    return config.assert_dict[var3]
                else:
                    return "非内网IP"
        else:
            return "忽略IPV6"
    except Exception:
        return f"{ip} 非IP"


def request_server(request_data) -> list:
    list1 = []
    for dev in config.dev_list:
        try:
            data = requests.Session().post(url=CONN_CS(dev[0], dev[1]).url_type(0), data=request_data, timeout=2000,
                                           headers=CONN_CS(dev[0], dev[1]).req_header).content.decode('utf-8')
            json_data = json.loads(data)
            if json_data['code'] != 0 and json_data['message'] != "成功":
                msg = "0x02 === 从服务器请求到的数据出错，请检查请求体是否正确！"
                print(msg)
                Feishu(msg).payload1()
                raise Error(msg)
            value = json_data['data']['records']  # 返回的是列表
            list1 += value
        except Exception:
            msg = f"0x01 === 请求 {dev[0]} 设备出错！{dev[0]} session失效或宕机！"
            print(msg)
            Feishu(msg).payload1()
    return list1


class Feishu:
    webhook = config.feishu_webhook
    secret = config.feishu_secret
    timestamp = str(round(time.time()))
    headers = {'Content-Type': 'application/json'}

    def __init__(self, message):
        self.message = message

    def sign(self):
        key = f"{self.timestamp}\n{self.secret}".encode('utf-8')
        HmacSHA256 = hmac.new(key=key, msg="".encode('utf-8'), digestmod=sha256).digest()
        return base64.b64encode(HmacSHA256).decode('utf-8')

    def payload1(self):
        data = {
            "timestamp": self.timestamp,
            "sign": self.sign(),
            "msg_type": "text",
            "content": {
                "text": self.message
            }
        }
        response = requests.post(url=self.webhook, data=_json(data).encode('utf-8'), headers=self.headers,
                                 proxies={'http': config.http_proxy, 'https': config.http_proxy})
        if response.status_code != 200:
            raise Error("向飞书群发送数据出错")
        s = response.content.decode('utf-8', 'ignore')
        # print(s)

    def payload2(self):
        # 时间 30天第一次事件发生的时间 源IP 源IP归属 目的IP 目的IP归属 今天的所有事件 30天的源IP对目的IP的所有事件 30天内事件发生的所有次数 今天出现的次数(昨天23:30到现在)
        for _ in self.message:
            rec_time = _[0]
            first_time = _[1]
            srcIp = _[2]
            srcIp_info = _[3]
            destIp = _[4]
            destIp_info = _[5]
            today_events = _[6]
            all_events = _[7]
            all_count = _[8]
            today_count = _[9]

            # print(rec_time, first_time, srcIp, srcIp_info, destIp, destIp_info, today_events, all_events, today_count,
            #       all_count)

            data = {
                "timestamp": self.timestamp,
                "sign": self.sign(),
                "msg_type": "interactive",
                "card": {
                    "config": {"wide_screen_mode": True}, "elements": [{"fields": [
                        {"is_short": True, "text": {"content": f"**时间**\n{rec_time}", "tag": "lark_md"}},
                        {"is_short": True, "text": {"content": f"**时间-30天**\n{first_time}", "tag": "lark_md"}},
                        {"is_short": True, "text": {"content": f"\r**源IP**\n{srcIp}", "tag": "lark_md"}},
                        {"is_short": True, "text": {"content": f"\r**源IP归属**\n{srcIp_info}", "tag": "lark_md"}},
                        {"is_short": True, "text": {"content": f"\r**目的IP**\n{destIp}", "tag": "lark_md"}},
                        {"is_short": True, "text": {"content": f"\r**目的IP归属**\n{destIp_info}", "tag": "lark_md"}},
                        {"is_short": True,
                         "text": {"content": f"\r**事件次数-今天**\n{today_count}", "tag": "lark_md"}},
                        {"is_short": True, "text": {"content": f"\r**事件次数-30天**\n{all_count}", "tag": "lark_md"}},
                        {"is_short": True, "text": {"content": f"\r**事件-今天**\n{today_events}", "tag": "lark_md"}},
                        {"is_short": True, "text": {"content": f"\r**事件-30天**\n{all_events}", "tag": "lark_md"}}],
                        "tag": "div"}, {"tag": "hr"}, {"elements":
                        [{
                            "content": "时间-30天：30天内事件第一次告警的时间\n事件-30天：30天内发生了哪些事件\n事件次数-30天：30天内发生多少次告警事件",
                            "tag": "lark_md"}],
                        "tag": "note"}],
                    "header": {"template": "green", "title": {"content": f"{rec_time[:10]} 告警", "tag": "plain_text"}}
                }
            }
            response = requests.post(url=self.webhook, data=_json(data).encode('utf-8').decode('latin1'),
                                     headers=self.headers,
                                     proxies={'http': config.http_proxy, 'https': config.http_proxy})
            if response.status_code != 200:
                raise Error("向飞书群发送数据出错")
            s = response.content.decode('utf-8', 'ignore')
            # print(s)

    def payload3(self):
        ip1 = self.message[0]
        ip2 = self.message[1]
        count1 = self.message[2]
        ip5 = self.message[3]
        ip5_info = self.message[4]
        ip6 = self.message[5]
        ip6_info = self.message[6]
        count3 = self.message[7]

        ip3 = self.message[8]
        ip4 = self.message[9]
        count2 = self.message[10]
        ip7 = self.message[11]
        ip7_info = self.message[12]
        ip8 = self.message[13]
        ip8_info = self.message[14]
        count4 = self.message[15]
        ttime = self.message[16]
        data = {
            "timestamp": self.timestamp,
            "sign": self.sign(),
            "msg_type": "interactive",
            "card": {
                "config": {"wide_screen_mode": True}, "elements": [{"fields": [{"is_short": False, "text": {
                    "content": f"**疑似攻击:**\n攻击IP：{ip1}\n受害IP：{ip2}\n攻击总次数：{count1}次\n***源IP*** {ip5} - {ip5_info}；***目的IP*** {ip6} - {ip6_info}；***产生了最多次的攻击事件*** {count3} 次",
                    "tag": "lark_md"}}, {"is_short": False, "text": {
                    "content": f"**\n误报事件:**\n源IP：{ip3}\n目的IP：{ip4}\n误报总次数：{count2}\n***源IP*** {ip7} - {ip7_info}；***目的IP*** {ip8} - {ip8_info}；***产生了最多次的误报事件*** {count4} 次",
                    "tag": "lark_md"}}], "tag": "div"}, {"tag": "hr"}, {"elements": [
                    {"content": f"00:00:00-{ttime[11:19]}", "tag": "lark_md"}], "tag": "note"}],
                "header": {"template": "red", "title": {"content": f"截止{ttime}报告", "tag": "plain_text"}}
            }
        }
        response = requests.post(url=self.webhook, data=_json(data).encode('utf-8').decode('latin1'),
                                 headers=self.headers,
                                 proxies={'http': config.http_proxy, 'https': config.http_proxy})
        if response.status_code != 200:
            raise Error("向飞书群发送数据出错")
        s = response.content.decode('utf-8', 'ignore')
        # print(s)


class Error(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


if __name__ == '__main__':
    while True:
        time1 = time.time()
        req_startTime = (datetime.datetime.now() - datetime.timedelta(seconds=config.sTime_seconds,
                                                                      minutes=config.sTime_minutes,
                                                                      hours=config.sTime_hours)).strftime(
            '%Y-%m-%d %H:%M:%S')  # 服务器请求数据开始时间
        req_endTime = (datetime.datetime.now() - datetime.timedelta(seconds=config.eTime_seconds,
                                                                    minutes=config.eTime_minutes,
                                                                    hours=config.eTime_hours)).strftime(
            '%Y-%m-%d %H:%M:%S')  # 服务器请求数据结束时间

        print(f"S/{req_startTime}, E/{req_endTime}")
        func1(request_server(request_param(beginTime=req_startTime, endTime=req_endTime, pageSize=1000000)))
        time2 = time.time()
        time_interval = config.INTERVAL - (time2 - time1)
        if time_interval > 0:
            print(f"监控中，当前监控频率{config.INTERVAL}秒每次，{str(time_interval)}秒后继续...\n")
            time.sleep(time_interval)
