#! /usr/bin/python3

# logging imported / used to supress ipv6 error message
import random
import logging
from sys import stdout
from argparse import ArgumentParser
from prettytable import PrettyTable
from scapy.all import sr1, IP, ICMP
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


def icmpScanner(IPs, timeOut):
    returnList = []
    random.shuffle(IPs)
    for index, tgt in enumerate(IPs):
        progress(index, len(IPs), tgt)
        ICMP_resp = sr1(IP(dst=str(tgt)) / ICMP(), timeout=timeOut,
                        verbose=0)
        if (str(type(ICMP_resp)) == "<class 'NoneType'>"):
            pass
        elif int(ICMP_resp.getlayer(ICMP).type) == 0 and int(
               ICMP_resp.getlayer(ICMP).code) == 0:
            returnList.append([tgt, 'Up'])
    return returnList


def progress(count, total, status=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)

    stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', status))
    stdout.flush()


def main():
    parser = ArgumentParser(
        description="Basic syn scanner Syn->Syn/Ack->RST")
    parser.add_argument("IP", nargs="+", help="Tgt IP(s)", type=str)
    parser.add_argument('-to', '--timeOut', help='Time Out',
                        type=int, default="1")
    args = parser.parse_args()

    returnList = icmpScanner(IPtoList(args.IP), args.timeOut)
    chart = PrettyTable()
    print('\n Only systems that responded are displayed')
    chart.field_names = ['IP', 'Status']
    returnList.sort()
    for record in returnList:
        chart.add_row(record)
    print(chart)


if __name__ == "__main__":
    main()
