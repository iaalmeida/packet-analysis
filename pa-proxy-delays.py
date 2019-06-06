#!/usr/bin/env python
# -*- coding: latin-1 -*-
'''
Analyse tcp packet delays in a PCAP file
notes: I had to assume that the proxy preserve the original port
Usage: __file__ [-s 10.80.250.21] -t 13.107.18.11 capture.cap
'''

import os, sys
import argparse
import pyshark
from ipaddress import ip_network, ip_address

# Versioning
__author__ = 'Ivo Almeida'
__copyright__ = 'Copyright 2019, Millennium bcp'
__version__ = '1.1.0'
__maintainer__ = 'Ivo Almeida'
__email__ = 'ivo.almeida@millenniumbcp.pt'

# Parsing options
parser = argparse.ArgumentParser(description='Analyse tcp packet delays in a PCAP file')
parser.add_argument('-V', '--version', action='store_true', help='show version')
parser.add_argument('-v', '--verbose', action='store_true', help='verbose')
parser.add_argument('-d', '--delay', default='0.1', type=float, help='max accepted delay to be considered as normal')
parser.add_argument('-p', '--proxy', metavar='NET/MASK[;...]', default='85.88.140.104/29; 88.157.230.0/24; 88.157.231.0/24', help='proxy network in use')
#parser.add_argument('-s', '--source', dest='src', metavar='HOST', help='source address to diagnose')
parser.add_argument('-t', '--target', dest='dst', metavar='HOST', default='40.101.92.194', help='target destination to diagnose')
#parser.add_argument('-d', '--debug', action='store_true', help='debug')
parser.add_argument('file', default='capture.cap', help='tcpdump file to analyse')
args = parser.parse_args()

if args.version:
    print(f'{sys.argv[0]} version {__version__}', file=sys.stderr)
    exit(0)

stats = dict.fromkeys(['pkts', 'flows', 'delayed'], 0)
proxies = [ (proxy.strip()) for proxy in args.proxy.split(';') ] 


def print_header():
    ''' prints the header with the info for this session '''

    print(f"Using {args.dst} as destination host and ...")
    print(f"  {proxies} as the proxies networks")
    print(f"  {args.delay}s as maximum accepted delay")
    print('----------' * 7)
#---


def print_stats():
    ''' prints the stats for this session '''

    print('----------' * 7 + "\nSession statistics:")
    print(f"  {stats['pkts']} total packets processed")
    print(f"  {stats['flows']} flows analysed")
    value = stats['delayed'] / stats['flows'] * 100
    print(f"  {stats['delayed']} packets with processed time greater than {args.delay}s ({value:.3}%)")
#--- 


def print_flow(flow):
    ''' print a flow from e to the proxy '''

    att = ' '
    time0 = float(flow[0].frame_info.time_relative)
    time1 = float(flow[1].frame_info.time_relative)
    delta = time1 - time0
    if args.verbose or delta >= args.delay:
        if delta >= args.delay:
            stats['delayed'] += 1
            att = '*'
        print(f'{att} | {flow[0].frame_info.number:>4},{flow[1].frame_info.number:<4} | {delta:.4f}', end='')
        print(f' | {flow[0].ip.src}:{flow[0].tcp.srcport} -> {flow[1].ip.dst}:{flow[1].tcp.dstport}')

#---


if __name__ == '__main__':
    # Open saved trace file
    if not os.path.isfile(args.file):
        print(f"'{args.file}' does not exist", file=sys.stderr)
        exit(-1)
    cap = pyshark.FileCapture(args.file, display_filter='tcp')

    print_header()
    flow = { }
    for pkt in cap:
        stats['pkts'] += 1
        if pkt.frame_info.protocols.split(':')[-1] != 'tcp':  #applicational packet
            continue
        psrc, pdst, pnumber = pkt.ip.src, pkt.ip.dst, pkt.frame_info.number
        if pdst == args.dst:  #* client -> server
            pport = pkt.tcp.srcport
            if not any(ip_address(psrc) in ip_network(proxy) for proxy in proxies):  #* client -> proxy
                if not flow.get(pport):  # it's a new flow
                    flow[pport] = []
                flow[pport].append(pkt)
            else:               #* proxy -> server
                if flow.get(pport):  # already known flow
                    stats['flows'] += 1
                    flow[pport].append(pkt)
                    print_flow(flow[pport])
                    del flow[pport]
                elif args.verbose:
                    print(f'Unknown flow, packet #{pkt.frame_info.number}: {psrc} -> {pdst}:{pport}')
        elif psrc == args.dst:  #* server -> client
            pport = pkt.tcp.dstport
            if any(ip_address(pdst) in ip_network(proxy) for proxy in proxies):  #* server -> proxy
                if not flow.get(pport):  # it's a new flow
                    flow[pport] = []
                flow[pport].append(pkt)
            else:               #* proxy -> client
                if flow.get(pport):  # have to be a know flow
                    stats['flows'] += 1
                    flow[pport].append(pkt)
                    print_flow(flow[pport])
                    del flow[pport]
                elif args.verbose:
                    print(f'Unknown flow, packet #{pkt.frame_info.number}: {psrc} -> {pdst}:{pport}')
        else:
            if args.verbose:
                print(f'non interesting packet #{pkt.frame_info.number}: {psrc} -> {pdst}:{pport}')
    #--- for pkt in cap:
    print_stats()

#--- main
exit(0)