# _*_ coding:utf-8 _*_

"""
-------------------------------------------------
@Author: dearest
@Data: 2022/12/23 20:30
@File: config.py
@Version: 1.0.0
@Description: TODO
@Question: NO
-------------------------------------------------
"""
import numpy as np

INTERVAL = 300  # 监控频率，xxx秒一次，建议300秒
sTime_seconds = 600  # 请求服务器的开始时间，比当前系统时间提前xxx秒
sTime_minutes = 0  # 同上
sTime_hours = 0  # 同上
eTime_seconds = 300  # 请求服务器的结束时间，比当前系统时间提前xxx秒。结束时间必须小于开始时间
eTime_minutes = 0  # 同上
eTime_hours = 0  # 同上

sqlite_position = "assert_nei.db"  # sqlite3数据库所在位置，该数据库中记录了内网的资产表

redis_host = "127.0.0.1"  # redis主机，与redis配置文件中bind的地址保持一致
redis_port = "12345"  # redis端口，与redis配置文件中的端口保持一致
redis_password = ""  # redis密码，与redis配置文件中的密码保持一致
start_redis_command = ""  # 操作系统启动redis服务的命令

feishu_webhook = "https://open.feishu.cn/open-apis/bot/v2/"  # 飞书机器人url，为了发送消息到群里
feishu_secret = "xxx"  # 飞书机器人密钥

http_proxy = "http://1.1.1.1:22"  # 内网代理地址，出网使用

dev_list = [
    ['1.1.1.1', 'JSESSIONID=xxx'],
    ['2.2.2.2', 'JSESSIONID=xxx']
]  # cs设备的ip和session，如有添加，请按照列表形式添加

# 源IP白名单，包含扫描器IP、代理IP
source_ip_white_list = np.array(['3.3.3.3','4.4.4.4'])
# 目的IP白名单
destination_ip_white_list = np.array(['5.5.5.5','6.6.6.6'])
# 源IP黑名单
source_ip_black_list = np.array(["4.4.4.4"])
# 目的IP黑名单
destination_ip_black_list = np.array(["5.5.5.5"])
# 事件白名单
eventName_white_list = np.array(["yes"])
# 事件黑名单
eventName_black_list = np.array(["no"])

assert_dict = {
    "5.5.5.": "xx系统",
    "6.6.": "yy系统",
    "7.": "未录入"
}
