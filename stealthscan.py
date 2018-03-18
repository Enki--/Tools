#! /usr/bin/python3

# logging imported / used to supress ipv6 error message
import logging
from sys import platform
from subprocess import Popen
from argparse import ArgumentParser
from prettytable import PrettyTable
from scapy.all import sr, sr1, IP, TCP, RandShort
from netaddr import valid_ipv4, iter_iprange, IPNetwork, IPAddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def parse_range(iprange):
    octets = iprange.split(".")
    start, end = octets[-1].split('-')
    mask = '.'.join(octets[:-1]) + '.'
    return mask + str(start), mask + str(end)


def IPtoList(IPs):
    # Handles the following formats
    # 192.168.1.1
    # 192.168.1.1-200
    # 192.168.1.0/24
    ipList = []
    for value in IPs:
        value = value.replace(',', '')
        if valid_ipv4(value):
            ipList.append(IPAddress(value))
        elif "-" in value:
            temp = parse_range(value)
            if valid_ipv4(temp[0]) and valid_ipv4(temp[1]):
                for item in iter_iprange(temp[0], temp[1]):
                    ipList.append(IPAddress(item))
        elif "/" in value:
            try:
                for ip in IPNetwork(value).iter_hosts():
                    ipList.append(IPAddress(ip))
            except ValueError:
                pass
        else:
            print(value + " is not valid IP or IP range, try again")
    return ipList


def stealthScanner(IPs, ports, ttl, scrPort, timeOut):
    scanResults = []
    if scrPort == 0:
        srcPort = int(RandShort())
    for tgt in IPs:
        if platform == 'linux':
            p = Popen(["iptables", "-A", "OUTPUT", "-p", "tcp", "--tcp-flags",
                      "RST", "RST", "-d", str(tgt), "-j" "DROP"])
        print("working on " + str(tgt))
        for tgtPort in ports:
            stealth_scan_resp = sr1(IP(dst=str(tgt), ttl=ttl) /
                                    TCP(sport=srcPort,
                                        dport=tgtPort,
                                        flags="S"),
                                    timeout=timeOut,
                                    verbose=False)

            if(str(type(stealth_scan_resp)) == "<class 'NoneType'>"):
                scanResults.append([tgt, tgtPort, "No Response"])
            elif(stealth_scan_resp.haslayer(TCP)):
                if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
                    send_rst = sr(IP(dst=str(tgt), ttl=ttl) /
                                  TCP(sport=srcPort,
                                      dport=tgtPort,
                                      flags="R"),
                                  timeout=timeOut,
                                  verbose=False)
                scanResults.append([tgt, tgtPort, "Open"])
            elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
                scanResults.append([tgt, tgtPort, "Closed"])
            elif(stealth_scan_resp.haslayer(ICMP)):
                if(int(stealth_scan_resp.getlayer(ICMP).type) == 3 and
                   int(stealth_scan_resp.getlayer(ICMP).code) in
                   [1, 2, 3, 9, 10, 13]):
                    scanResults.append([tgt, tgtPort, "Filtered"])
        if platform == 'linux':
            p = Popen(["iptables", "-D", "OUTPUT", "-p", "tcp", "--tcp-flags",
                       "RST", "RST", "-d", str(tgt), "-j" "DROP"])
    return scanResults


def main():
    parser = ArgumentParser(
        description="Basic syn scanner Syn->Syn/Ack->RST")
    parser.add_argument("IP", nargs="+", help="Tgt IP(s)", type=str)
    parser.add_argument('-p', '--port', nargs='*', help='Tgt ports',
                        type=int, default="80")
    parser.add_argument('-t', '--ttl', help='TTL', type=int, default="128")
    parser.add_argument('-sp', '--srcPort', help='Src Port',
                        type=int, default="0")
    parser.add_argument('-to', '--timeOut', help='Time Out',
                        type=int, default="1")
    args = parser.parse_args()

    returnList = stealthScanner(IPtoList(args.IP), args.port, args.ttl,
                                args.srcPort, args.timeOut)

    chart = PrettyTable()
    chart.field_names = ['IP', 'Port', 'Status']
    for record in returnList:
        chart.add_row(record)
    print(chart)


if __name__ == "__main__":
    main()
