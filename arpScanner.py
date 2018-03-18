#! /usr/bin/python3

# logging imported / used to supress ipv6 error message
import logging
from argparse import ArgumentParser
from prettytable import PrettyTable
from scapy.all import srp, Ether, ARP
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


def arpScanner(IPs):
    returnList = []
    for tgt in IPs:
        ans, unas = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                        ARP(pdst=str(tgt)), timeout=2,
                        verbose=False)
        for s, r in ans:
            result = r.sprintf("%ARP.psrc% %Ether.src%")
            returnList.append(result.split(' '))
    return returnList


def main():
    parser = ArgumentParser(
        description="Basic syn scanner Syn->Syn/Ack->RST")
    parser.add_argument("IP", nargs="+", help="Tgt IP(s)", type=str)
    args = parser.parse_args()

    returnList = arpScanner(IPtoList(args.IP))
    chart = PrettyTable()
    print('Only systems that responded are displayed')
    chart.field_names = ['IP', 'MAC']
    for record in returnList:
        chart.add_row(record)
    print(chart)


if __name__ == "__main__":
    main()
