#!/usr/bin/python
# -*- coding:utf8 -*-
# Python:          2.7.13
# Platform:        Windows
# Authro:          s3xy


import platform
import getopt
import sys
import os
import thread
import requests
from lxml import etree
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import socket, time, thread, signal
socket.setdefaulttimeout(3)


def socket_port(ip, port):
#scan target open ports
    try:
        if port >= 65535:
            pass
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((ip, port))
        # banner = s.recv(1024)
        if result == 0:
            lock.acquire()
            print '   port: %s' %port
            lock.release()
        s.close()
    except:
        pass


def ip_scan(ip):
#default moudle
    try:
        tmp = open('port.txt').readlines()
        for i in tmp:
            domain = i.strip()
            thread.start_new_thread(socket_port,(ip,int(i.strip())))
        time.sleep(0.2)
    except:
        print '\033[1;31m[-]Missing file: port.txt\033[0m'


def get_os():
    os = platform.system()
    if os == "Windows":
        return "n"
    else:
        return "c"


def ping_ip(ip_str):
    cmd = ["ping", "-{op}".format(op=get_os()),
           "1", ip_str]
    output = os.popen(" ".join(cmd)).readlines()
    flag = False
    for line in list(output):
        if not line:
            continue
        if str(line).upper().find("TTL") >= 0:
            flag = True
            break
    if flag:
        lock.acquire()
        print '\033[1;32m[+]scan: %s\033[0m' %ip_str
        ip_scan(ip_str)
        lock.release()


def find_ip(ip_prefix):
    for i in range(1, 256):
        ip = '%s.%s' % (ip_prefix, i)
        thread.start_new_thread(ping_ip, (ip,))
        time.sleep(0.3)


def domain_port(url):
    try:
        tmp = open(url).readlines()
        if len(tmp[0].split()) == 2:
        #target is subDomainsBrute file
            dict = {}
            for i in tmp:
                ip = i.split()[1].rstrip(',')
                domain = i.split()[0]
                if not ip.startswith(('192.', '10.', '127.', '172.')):
                    dict.setdefault(ip,[]).append(domain)
            for j in dict:
                print '\033[1;32m[+]scan: %s\033[0m\n   site: %s' % (j, ', '.join(dict[j]))
                ip_scan(j)

        elif tmp[0].strip().split('.')[-1].isdigit():
        #target is ip file
            dict = []
            for i in tmp:
                ip = i.strip()
                if not ip.startswith(('192.', '10.', '127.', '172.')):
                    dict.append(ip)
            for j in dict:
                print '\033[1;32m[+]scan %s\033[0m' % j
                ip_scan(j)

        else:
        #target is domain file
            dict = {}
            for i in tmp:
                domain = i.strip()
                ip = socket.gethostbyname(domain)
                if not ip.startswith(('192.', '10.', '127.', '172.')):
                    dict.setdefault(ip,[]).append(domain)
            for j in dict:
                print '\033[1;32m[+]scan %s\033[0m   %s' % (j, ', '.join(dict[j]))
                ip_scan(j)
    except Exception as e:
        print e



def get_title(url, f):
#get web title
    tmp = os.popen("cat %s | awk '{print $1}'" %url).readlines()
    for i in tmp:
        url = i.strip()
        try:
            url = 'http://%s' %url
            res = requests.get(url, timeout=3)
            res.encoding = 'UTF-8'
            soup = BeautifulSoup(res.text, 'html.parser')
            for i in soup.findAll('title'):
                if f:
                    title_dict = open(f).readlines()
                    for j in title_dict:
                        if j.strip().decode('utf-8') in i.string:
                            print '[+]%s --- %s' %(url.strip('http://'), i.string)
                else:
                    print '[+]%s --- %s' %(url.strip('http://'), i.string)
        except:
            pass


def main(argv):
    ip = ''
    port = ''
#get input command
    try:
        options, args = getopt.getopt(argv, 'hi:p:c:t:f:', ['help', 'ip=', 'port=', 'c=', 't=', 'f='])
    except getopt.GetoptError:
        sys.exit()

    for option, value in options:
        if option in ('-h', '--help'):
            print '''\033[1;33m
            _______
    .-----.|   |   |.---.-.-----.
    |  .  ||       ||  .  |  .  |
    |   __||__|_|__||___._|   __|      v1.0.5
    |__|                  |__|         www.xusec.com

            \npMap.py [options]
            -h,--help       [help]
            -i,--ip         [scan single ip, txt file, ip-255]
            -p,--port       [single port to scan]
            null            [default port to scan]
            -c              [scan ip C part]
            -t (-f)         [scan domain file web title (from dict)]\033[0m'''
            sys.exit()

        if option in ('-i', '--ip'):
            if '.txt' in value:
                domain_port(value)
                return 0
            else:
                if '-' in value:
                    ip_prefix = '.'.join(value.split('.')[:-1])
                    ip_range = '.'.join(value.split('.')[-1:])
                    ip_min = int('-'.join(ip_range.split('-')[:-1]))
                    ip_max = int('-'.join(value.split('-')[-1:]))+1
                    for i in range(ip_min, ip_max):
                        ip = '%s.%s' % (ip_prefix, i)
                        thread.start_new_thread(ping_ip, (ip,))
                        time.sleep(0.3)
                    return 0
                else:
                    ip = value

        if option in ('-p', '--port'):
            if str.isdigit(value):
                port = value
            else:
                print 'port is not num!'
                return 0

        if option in ('-c'):
            print 'scann all'
            ip_prefix = '.'.join(value.split('.')[:-1])
            find_ip(ip_prefix)
            return 0

        if option in ('-t'):
            f = ''
            if len(options) == 2:
                f = options[1][1]
                get_title(value, f)
            else:
                get_title(value, f)
            exit()

    if not port:
        print '\033[1;32m[+]scan: %s\033[0m' %ip
        ip_scan(ip)
    else:
        socket_port(ip, int(port))


def quit(signum, frame):
    print '\033[1;31m[-]All scan exit\033[0m'
    sys.exit()


if __name__ == '__main__':
    try:
        start_time = time.time()
        signal.signal(signal.SIGINT, quit)
        signal.signal(signal.SIGTERM, quit)
        lock = thread.allocate_lock()
        main(sys.argv[1:])
        while True:
            print '\033[1;32m[+]All scan finish, time: %.2fs\033[0m' %(time.time()-start_time)
            sys.exit()
    except Exception, exc:
        print exc
