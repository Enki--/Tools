#! /usr/bin/python

#logging imported / used to supress ipv6 error message
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import subprocess
from scapy.all import sr, sr1, IP, TCP, RandShort

dst_ip = "216.58.219.36"
src_port = 2525
dst_port=80
set_ttl=128

p = subprocess.Popen(["iptables", "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-d", dst_ip, "-j" "DROP"], stdout=subprocess.PIPE)

stealth_scan_resp = sr1(IP(dst=dst_ip,ttl=set_ttl)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=2, verbose=False)
if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
    print("Filtered")
elif(stealth_scan_resp.haslayer(TCP)):
    if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
        send_rst = sr(IP(dst=dst_ip,ttl=set_ttl)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=2, verbose=False)
    print("Open")
elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
    print("Closed")
elif(stealth_scan_resp.haslayer(ICMP)):
    if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
        print("Filtered")

p = subprocess.Popen(["iptables", "-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-d", dst_ip, "-j" "DROP"], stdout=subprocess.PIPE)
