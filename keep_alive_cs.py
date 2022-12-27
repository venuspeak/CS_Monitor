# -*-coding=utf-8 -*-
# _*_ author:dearest _*_
import json, datetime, time, requests, os, redis
import numpy as np
import pandas as pd
import schedule
import platform
import config


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
        pool = redis.ConnectionPool(host=host, port=port, password=password)
        self.conn = redis.Redis(connection_pool=pool, decode_responses=True)

    def __del__(self):
        """程序结束，关闭连接池，释放资源"""
        self.conn.connection_pool.disconnect()

    def set_expire_by_day(self, name, second=60 * 60 * 24 * 15):
        """设置name的过期时间，默认15天"""
        return self.conn.expire(name, time=second)

    def remove_expire(self, name):
        """移除name的过期时间，name将保持持久"""
        return self.conn.persist(name)

    def rename(self, old, new):
        """重命名name"""
        if self.exists(old):
            return self.conn.rename(old, new)

    def exists(self, name):
        """检查name是否存在"""
        return self.conn.exists(name)

    def get_expire_by_second(self, name):
        """以秒为单位返回name的剩余过期时间"""
        return self.conn.ttl(name)

    def rules(self, rule, srcIp, destIp, eventName, srcPort, destPort, eventLevel):
        """
        rule分为rule1跟rule2
        1、rule1 里面是只有一个事件
        2、rule2 里面是大于一个事件
        """
        key = f"{srcIp}_{destIp}"
        dict_data = {
            "srcIp": srcIp,
            "destIp": destIp,
            "eventName": eventName,
            "srcPort": srcPort,
            "destPort": destPort,
            "eventLevel": eventLevel,
        }
        value = _json(dict_data)

        if self.conn.hexists(name=rule, key=key):
            print("该键 %s 已存在。具体为: " + self.conn.hget(name=rule, key=key) % key)
        else:
            self.conn.hset(name=rule, key=key, value=value)
            print(f"已创建 {key} 这个键")
        self.__del__()

    def event_of_30_days(self):
        time1 = time.time()
        name = "events" + (datetime.datetime.now() - datetime.timedelta(days=1)).strftime(
            '%Y%m%d')  # 每天0点更新30天的所有事件特征
        endTime = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y-%m-%d 23:00:00')
        beginTime = (datetime.datetime.now() - datetime.timedelta(days=3)).strftime('%Y-%m-%d 00:00:00')
        print(f"键名：{name}  开始时间：{beginTime}  结束时间：{endTime}")

        import analysis_nw_data
        A = analysis_nw_data.request_param(beginTime=beginTime, endTime=endTime, pageSize=2000000)
        print("=====开始请求服务器")
        B = analysis_nw_data.request_server(A)
        print("=====请求服务器数据结束")
        C = np.array(B)
        print(C.shape)
        D = []
        for element in C.flat:
            eventTime = element['eventTimeStr']
            eventName = element['eventName']
            srcIp = element['srcipStr']
            destIp = element['dstipStr']
            srcPort = element['srcport']
            destPort = element['dstport']
            eventLevel = element['eventlevel']

            D.append([eventName, srcIp, destIp, srcPort, destPort, eventLevel, eventTime, 0])
        E = np.array(D)
        print(E.shape)
        # 分组去重排序后的列：b h a c d e f g  对应： 源IP 计数 事件名 目的IP 源端口 目的端口 事件等级 时间
        df = pd.DataFrame(E, columns=["a", "b", "c", "d", "e", "f", "g", "h"])
        new_df = df.groupby(["b", "c"]).agg(
            {"a": np.unique, "d": np.unique, "e": np.unique, "f": np.unique, "g": np.sort, "h": "count"})
        F = np.array(new_df.to_records())
        for element in F.flat:
            srcIp = element[0]
            destIp = element[1]
            eventName = element[2]
            srcPort = element[3]
            destPort = element[4]
            eventLevel = element[5]
            eventTime = element[6]
            count = element[7]
            key = f"{srcIp}_{destIp}"
            dict_data = {
                "srcIp": srcIp,
                "destIp": destIp,
                "eventName": eventName.tolist(),
                "srcPort": srcPort.tolist(),
                "destPort": destPort.tolist(),
                "eventLevel": eventLevel.tolist(),
                "first30": eventTime[0],
                "last30": eventTime[-1],
                "count": str(count)
            }
            value = _json(dict_data)
            self.conn.hset(name=name, key=key, value=value)

        self.set_expire_by_day(name=name)  # 设置15天的过期时间
        self.__del__()  # 释放连接资源
        time2 = time.time()
        print(f"耗时 {time2 - time1} 秒.")


def dev_alive():
    import analysis_nw_data
    for dev in config.dev_list:
        if requests.get(url=analysis_nw_data.CONN_CS(dev[0], dev[1]).url_type(2),
                        headers=analysis_nw_data.CONN_CS(dev[0], dev[1]).req_header, timeout=1000).status_code == 200:
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + f" {dev[0]} 设备正常......")
        else:
            print(f"{dev[0]} 设备session失效或宕机!!!")


def redis_alive():
    result = ''
    sys_platform = platform.platform().lower()
    if "linux" in sys_platform:
        result = os.popen(f'lsof -i:{config.redis_port}').read()
    elif "macos" in sys_platform:
        result = os.popen(f'lsof -i:{config.redis_port}').read()
    elif "windows" in sys_platform:
        result = os.popen(f'netstat -ano |findstr "{config.redis_port}"').read()

    if result == "":
        os.system(config.start_redis_command)
        print(f"redis服务已启动，端口号为{config.redis_port}，继续运行.....")
    else:
        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " redis服务运行正常......")


def db_exists():
    if not os.path.exists(config.sqlite_position):
        print(f"{config.sqlite_position} 目录下没有sqlite数据库，请检查后重新运行该脚本!!!")
        exit()
    else:
        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " sqlite3数据库运行正常.....")


def create_folder():
    folder_path = os.getcwd()
    isExists_excel1 = os.path.exists(folder_path + '/excel_wu_bao')
    isExists_excel2 = os.path.exists(folder_path + '/excel_event')
    isExists_log = os.path.exists(folder_path + '/log')
    if not isExists_excel1:
        os.mkdir(folder_path + '/excel_wu_bao')
        print('excel_wu_bao 目录创建成功!')
    else:
        print('excel_wu_bao 目录已存在，继续执行...')
    if not isExists_excel2:
        os.mkdir(folder_path + '/excel_event')
        print('excel_event 目录创建成功！')
    else:
        print('excel_event 目录已存在，继续执行...')
    if not isExists_log:
        os.mkdir(folder_path + '/log')
        print('log 目录创建成功！')
    else:
        print('log 目录已存在，继续执行...')


def send_report():
    xlsx1 = os.getcwd() + "/excel_event/event_" + datetime.datetime.now().strftime("%Y_%m_%d") + ".xlsx"
    xlsx2 = os.getcwd() + "/excel_wu_bao/WuBao_" + datetime.datetime.now().strftime("%Y_%m_%d") + ".xlsx"
    ip1, ip2, ip3, ip4, count1, count2, info1, info2 = [], [], '', '', '', '', '', ''
    ip5, ip6, ip7, ip8, count3, count4, info3, info4 = [], [], '', '', '', '', '', ''
    ttime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if os.path.exists(xlsx1):
        df1 = pd.read_excel(xlsx1)
        if len(df1.index) > 0:
            A1 = df1.groupby('源IP').agg({'源IP': np.unique})
            A2 = df1.groupby('目的IP').agg({'目的IP': np.unique})  # 取出
            A3 = df1.groupby(['源IP', '目的IP']).agg({'今天出现的次数(昨天23:00到现在)': np.max})  # 取出以 源—目的 为键的最大值
            A4 = A3['今天出现的次数(昨天23:00到现在)'].sum()  # 计算攻击过次数总和
            A5 = df1.loc[df1['今天出现的次数(昨天23:00到现在)'].idxmax()]  # 取出最大值的那一行数据
            [ip1.append(_[0]) for _ in A1['源IP']]
            [ip2.append(_[0]) for _ in A2['目的IP']]
            count1 = A4
            ip3 = A5[2]
            ip4 = A5[4]
            info1 = A5[3]
            info2 = A5[5]
            count2 = A5[9]

    if os.path.exists(xlsx2):
        df2 = pd.read_excel(xlsx2)
        if len(df2.index) > 0:
            A1 = df2.groupby('源IP').agg({'源IP': np.unique})
            A2 = df2.groupby('目的IP').agg({'目的IP': np.unique})  # 取出
            print(type(A1))
            print(A1)
            A3 = df2.groupby(['源IP', '目的IP']).agg({'今天出现的次数(昨天23:00到现在)': np.max})  # 取出以 源—目的 为键的最大值
            A4 = A3['今天出现的次数(昨天23:00到现在)'].sum()  # 计算攻击过次数总和
            A5 = df2.loc[df2['今天出现的次数(昨天23:00到现在)'].idxmax()]  # 取出最大值的那一行数据
            [ip5.append(_[0]) for _ in A1['源IP']]
            [ip6.append(_[0]) for _ in A2['目的IP']]
            count3 = A4
            ip7 = A5[1]
            ip8 = A5[3]
            info3 = A5[2]
            info4 = A5[4]
            count4 = A5[8]
    data = [ip1, ip2, str(count1), ip3, info1, ip4, info2, str(count2), ip5, ip6, str(count3), ip7, info3, ip8, info4,
            str(count4), ttime]

    import analysis_nw_data
    analysis_nw_data.Feishu(data).payload3()


if __name__ == "__main__":
    create_folder()
    dev_alive()
    redis_alive()
    db_exists()
    schedule.every(3).minutes.do(dev_alive)  # 每隔3分钟执行一次
    schedule.every().hour.do(redis_alive)
    schedule.every().hour.do(db_exists)
    schedule.every().hour.do(create_folder)
    schedule.every().day.at("08:00").do(send_report)
    schedule.every().day.at("12:00").do(send_report)
    schedule.every().day.at("15:00").do(send_report)
    schedule.every().day.at("18:00").do(send_report)
    schedule.every().day.at("22:00").do(send_report)
    schedule.every().day.at("23:00").do(REDIS().event_of_30_days)  # 每天23：30分执行
    while True:
        schedule.run_pending()  # 运行所有可以运行的任务
    s = REDIS().conn.hgetall("events20221222")
    for k, v in s.items():
        ss = json.loads(v.decode('utf-8'))
        with open('events20221222.txt', 'a', encoding='utf-8') as ff:
            ff.write(
                f"{ss['srcIp']},{ss['destIp']},{ss['eventName']},{ss['srcPort']},{ss['destPort']},{ss['eventLevel']},{ss['first30']},{ss['last30']},{ss['count']}\n")

    pass

    # REDIS().event_of_30_days()
    # REDIS().conn.hgetall("rule2")
    # REDIS().rules("rule1","133.64.177.89","133.64.101.204",["HTTP_木马后门_webshell_JSP_oracle数据库操作木马"],["*"],["9980"],["30"])
    # REDIS().conn.hdel("rule2","133.64.177.89_133.64.101.204")
    # send_report()
