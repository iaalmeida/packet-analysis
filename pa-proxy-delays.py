#!/usr/bin/env python
# -*- coding: latin-1 -*-
'''
Analyse tcp packet delays in a PCAP file
Usage: __file__ -s 10.80.250.21 -t 40.101.92.194 capture.cap
'''

import sys
import argparse
import pyshark
from ipaddress import ip_network, ip_address

# Versioning
__author__ = 'Ivo Almeida'
__copyright__ = 'Copyright 2019, Millennium bcp'
__version__ = '1.0.0'
__maintainer__ = 'Ivo Almeida'
__email__ = 'ivo.almeida@millenniumbcp.pt'

# Parsing options
parser = argparse.ArgumentParser(description='Analyse tcp packet delays in a PCAP file')
parser.add_argument('-V', '--version', action='store_true', help='show version')
#parser.add_argument('-v', '--verbose', action='store_true', help='verbose')
parser.add_argument('-d', '--delay', default='0.1', type=float, help='max accepted delay to be considered as normal')
parser.add_argument('-p', '--proxy', metavar='NET/MASK', default='85.88.140.104/29', help='proxy network in use')
parser.add_argument('-s', '--source', dest='src', metavar='HOST', required=True, help='source address to diagnose')
parser.add_argument('-t', '--target', dest='dst', metavar='HOST', required=True, help='target destination to diagnose')
#parser.add_argument('-d', '--debug', action='store_true', help='debug')
parser.add_argument('file', default='capture.cap', help='tcpdump file to analyse')
args = parser.parse_args()

if args.version:
    print(f'{sys.argv[0]} version {__version__}', file=sys.stderr)
    exit(0)
'''
src = args.source
delay = float(args.delay)
proxy = args.proxy
dst = args.target
'''

# Open saved trace file
cap = pyshark.FileCapture(args.file, display_filter='tcp')

if __name__ == '__main__':
    print(f'Using {args.proxy} as the proxy network and {args.delay} as maximum accepted delay ...')
    flow = { }
    for pkt in cap:
        psrc, pdst = pkt.ip.src, pkt.ip.dst
        if psrc == args.src and pdst == args.dst:  # client -> server
            pport = pkt.tcp.srcport
            if not flow.get(pport):  # it's a new flow
                flow[pport] = []
            flow[pport].append(pkt)
        elif ip_address(psrc) in ip_network(args.proxy) and pdst == args.dst:  # proxy -> server
            #* let's assume that the proxy preserve ths original port
            pport = pkt.tcp.srcport
            if flow.get(pport):  # already known flow
                flow[pport].append(pkt)
        elif psrc == args.dst and ip_address(pdst) in ip_network(args.proxy):  # server -> proxy
            pport = pkt.tcp.dstport
            if flow.get(pport):  # have to be a know flow
                flow[pport].append(pkt)
            else:
                print(f'Unknown flow, packet #{pkt.frame_info.number}: {psrc} -> {pdst}:{pport}')
        elif psrc == args.dst and pdst == args.proxy:  # server -> client
            pport = pkt.tcp.dstport
            if flow.get(pport):  # have to be a know flow
                flow[pport].append(pkt)
            else:
                print(f'Unknown flow, packet #{pkt.frame_info.number}: {psrc} -> {pdst}:{pport}')
        else:
            pass  #* non interesting packet 

    for f in flow:
        print(f'\n-- port: {f} ' + '----------' * 5)
        time0 = float(flow[f][0].frame_info.time_relative)
        for p in flow[f]:
            stat = ''
            time1 = float(p.frame_info.time_relative)
            if ip_address(p.ip.src) in ip_network(args.proxy) and (time1 - time0) > args.delay:
                stat = '****'
            print(f'{p.frame_info.number:>4} | {time1-time0:.4f} | {p.ip.src}:{p.tcp.srcport} -> {p.ip.dst}:{p.tcp.dstport}  {stat}')
            time0 = time1

#--- main
exit(0)