#!/usr/bin/python
from binascii import hexlify
from scapy.all import sr1, IP, TCP
import nmap
import socket
import subprocess
import sys
import threading
import time


# ----------------------------------------------------------------------
def ping(host):
    ret = subprocess.call(['ping', '-c', '3', '-W', '5', host],
                          stdout=open('/dev/null', 'w'),
                          stderr=open('/dev/null', 'w'))
    return ret == 0


# ----------------------------------------------------------------------
def net_is_up(list_host):
    print "[%s] Checking if network is up..." % time.strftime(
        "%Y-%m-%d %H:%M:%S")
    xstatus = 1
    for h in list_host:
        if ping(h):
            print "[%s] Network is up!" % time.strftime(
                "%Y-%m-%d %H:%M:%S")
            xstatus = 0
            break
    if xstatus:
        print "[%s] Network is down :(" % time.strftime(
            "%Y-%m-%d %H:%M:%S")
    return xstatus


# ----------------------------------------------------------------------
def info():
    name = socket.gethostname()
    address = socket.gethostbyname(name)
    print "My host name: %s" % name
    print "My IP: %s" % address


# ----------------------------------------------------------------------
def info_remote(address):
    remote_host = str(address)
    try:
        print ("Romote host: %s" %
               remote_host)
        print ("Address IP: %s" %
               socket.gethostbyname(remote_host))
    except socket.error, err_msg:
        print "%s: %s" % (remote_host, err_msg)


# ----------------------------------------------------------------------
def ip_format(address_list):
    for dir_ip in address_list:
        host = socket.gethostbyname(str(dir_ip))
        packet_ip = socket.inet_aton(host)
        no_packet_ip = socket.inet_ntoa(packet_ip)
        print ("Ip: %s =>  %s,  %s" %
               (dir_ip, hexlify(packet_ip), no_packet_ip))


# ----------------------------------------------------------------------
def scan_port(remoteIP):
    subprocess.call('clear', shell=True)
    try:
        for port in range(1, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((remoteIP, port))
            if result == 0:
                print 'Port {}: \t Open'.format(port)
            sock.close
    except socket.gaierror:
        print 'IP could not be resolved. Exiting'
        sys.exit()
    except socket.erro:
        print 'Couldn\'t connect to server'
        sys.exit()


# ----------------------------------------------------------------------
def info_ipaddres(ipaddres):
    nm = nmap.PortScannerAsync()
    results = nm.scan(str(ipaddres))
    scan_info = nm.scaninfo()
    return nm.csv(), results, scan_info


# ----------------------------------------------------------------------
def scan_ipaddres_protocol_port(ipaddres, protocolo, port):
    nm = nmap.PortScannerAsync()
    return nm[str(ipaddres)][str(protocolo)][int(port)]['state']


# ----------------------------------------------------------------------
def block_ip(remoteIP):
    cmd = str('iptables -A INPUT -s %s -j DROP' %
              str(remoteIP))
    subprocess.call(cmd, shell=True)


# ----------------------------------------------------------------------
def accept_ip(remoteIP):
    cmd = str('iptables -A INPUT -d %s -j DROP' %
              str(remoteIP))
    subprocess.call(cmd, shell=True)


# ----------------------------------------------------------------------
OPEN_PORTS = []


def analyze_port(host, port, sem):
    print "[ii] Analizando el puerto %s" % port

    res = sr1(IP(dst=host) /
              TCP(dport=port),
              verbose=False,
              timeout=0.2)

    if res is not None and TCP in res:
        if res[TCP].flags == 18:
            OPEN_PORTS.append(port)
            print "Puerto %s abierto " % port
    sem.release()


def main(address, list_port):
    sem = threading.BoundedSemaphore(value=4)
    threads = []
    for x in list_port:
        t = threading.Thread(
            target=analyze_port,
            args=(str(address), x, sem, ))
        threads.append(t)
        t.start()
        sem.acquire()
    for x in threads:
        x.join()
    print "[*] Puertos abiertos:"
    for x in OPEN_PORTS:
        print "     - %s/TCP" % x
    print


if __name__ == '__main__':
    main("google.es", [80, 81])
# ----------------------------------------------------------------------
