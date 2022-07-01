# -*-coding=utf-8-*-

import time
import requests

def keep_alive(devList):
    for i in dev_list:
        try:
            dev_data = i.split(':')
            dev_ip = dev_data[0]
            dev_session = dev_data[1]
            req_url = "http://" + dev_ip + "/eventdisplay/saveCookie.action"
            req_cookie = {"JSESSIONID": dev_session}
            req_header = {"Content-Type": "Application/json;charset=UTF-8"}
            conn = requests.session()
            if conn.get(req_url, cookies=req_cookie, headers=req_header, timeout=10).status_code == 200:
                print(dev_ip + ' : 该设备访问成功！')
        except Exception as e:
            print(dev_ip + ' : 这个设备有问题！')


if __name__ == "__main__":
    dev_list = ['ip1:session1', 'ip2:session2','ip3:session3']  # cs设备的IP跟Session
    count = 0
    while 1:
        keep_alive(dev_list)
        count += 1
        print("已经执行keep_alive脚本  %d" % count + "次" + '\n')
        time.sleep(300)  # 每300秒执行一次