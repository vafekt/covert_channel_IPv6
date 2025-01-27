#!/usr/bin/env python3
import logging
import multiprocessing
import random
import sys
from argparse import ArgumentParser
from collections import Counter
from math import floor

import netifaces
import netifaces as ni
import psutil
from Cryptodome.Cipher import DES, AES
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, HBHOptUnknown, IPv6ExtHdrDestOpt, ICMPv6EchoReply, IPv6ExtHdrHopByHop, IPv6ExtHdrFragment, IPv6ExtHdrRouting
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP, UDP
from scapy.sendrecv import sendp, srp1, sniff, sendpfast
from scapy.volatile import RandString, RandShort

from validate_parameters import validate_file, is_valid_ipv6, is_valid_mac


def parameter():
    parser = ArgumentParser(description="|> Sending a file through Covert channel to a specified target, with option "
                                        "to encrypt (DES-CBC or AES-CBC algorithm) the file.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender.")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping).")
    parser.add_argument("-dmac", dest="destination_mac", action="store",
                        help="the MAC address of receiver (resolved from the interface if skipping).")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping).")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::1"
                                                                            " if skipping).")
    parser.add_argument("-t", dest="covert_type", choices=['TC', 'FL', 'NH', 'HL', 'HBH', 'RH', 'DO', 'FH'], action="store", default="DO",
                        help="choose one of 7 options to build covert channel (Traffic Class-TC, Flow Label-FL, Next Header-NH, Hop By Hop-HBH, Routing Header-RH, Destination Option-DO, Fragment Header-FH.")
    parser.add_argument("-i", dest="filename", action="store", type=validate_file,
                        help="input file to send.", metavar="FILE")
    parser.add_argument("-a", dest="algorithm", choices=['AES', 'DES'], action="store",
                        help="choose one of two options to encrypt (AES or DES).")
    parser.add_argument("-p", dest="protocol", choices=['IPv6', 'ICMPv6', 'UDP', 'TCP'], action="store", default="IPv6",
                        help="choose one of 3 options to build the protocol (IPv6, ICMPv6, UDP or TCP).")
    parser.add_argument("-k", dest="key", action="store", help="insert the key to encrypt the file using defined "
                                                               "algorithm (automatically generated if skipping).")
    args = parser.parse_args()

    # Validate the input
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    # Validate the network interface
    if not args.interface:
        print("---> Network interface is required!!!")
        parser.print_help()
        sys.exit(1)
    interface_list = netifaces.interfaces()
    while True:
        if args.interface in interface_list:
            break
        else:
            print("---> The given interface is invalid. Try again!!!")
            sys.exit(1)

    flag = False
    # Validate the source IPv6 address
    if args.source_ip is None:
        args.source_ip = ni.ifaddresses(args.interface)[ni.AF_INET6][0]['addr']
        args.source_ip = args.source_ip.replace("%", '')
        args.source_ip = args.source_ip.replace(args.interface, '')
    if args.source_ip is not None:
        if not is_valid_ipv6(args.source_ip):
            print("---> The given source IPv6 address is invalid. Try again!!!")
            flag = True

    # Validate the destination IPv6 address
    if args.destination_ip is None:
        args.destination_ip = "ff02::1"
    if args.destination_ip is not None:
        if not is_valid_ipv6(args.destination_ip):
            print("---> The given destination IPv6 address is invalid. Try again!!!")
            flag = True

    # Validate the source MAC address
    if args.source_mac is None:
        args.source_mac = get_if_hwaddr(args.interface)
    if args.source_mac is not None:
        if not is_valid_mac(args.source_mac):
            print("---> The given source MAC address is invalid. Try again!!!")
            flag = True

    # Validate the destination MAC address
    if args.destination_mac is not None:
        if not is_valid_mac(args.destination_mac):
            print("---> The given destination MAC address is invalid. Try again!!!")
            flag = True

    # Get the content of file
    if args.filename is None:
        print("---> No file is included. Try again!!!")
        flag = True
    if args.filename is not None:
        with open(args.filename, 'rb') as f:
            content = f.read()
            f.close()

    # Validate the key
    if args.key is None and args.algorithm is not None:
        if args.algorithm == "AES":
            args.key = "This is a key123"
        if args.algorithm == "DES":
            args.key = "This key"
    if args.key is not None and args.algorithm is not None:
        if args.algorithm == "AES":
            if len(args.key) < 16:
                while len(args.key) != 16:
                    args.key = args.key + " "
            if len(args.key) > 16:
                args.key = args.key[0:16]
        if args.algorithm == "DES":
            if len(args.key) < 8:
                while len(args.key) != 8:
                    args.key = args.key + " "
            if len(args.key) > 8:
                args.key = args.key[0:8]

    if flag:
        sys.exit(1)

    # Validate the encryption
    if args.algorithm == "AES":
        aes = AES.new(args.key.encode("utf8"), AES.MODE_CBC, 'This is an IV456'.encode("utf8"))
        extra = len(content) % 16
        if extra > 0:
            char = " ".encode("utf-8")
            content = content + (char * (16 - extra))
        content = aes.encrypt(content)
    if args.algorithm == "DES":
        des = DES.new(args.key.encode("utf8"), DES.MODE_CBC, 'This iv '.encode("utf8"))
        extra = len(content) % 8
        if extra > 0:
            char = " ".encode("utf-8")
            content = content + (char * (8 - extra))
        content = des.encrypt(content)

    return args.interface, args.source_mac, args.destination_mac, args.source_ip, args.destination_ip, args.covert_type, args.protocol, content


def generate(interface, source_mac, destination_mac, source_ip, destination_ip, type, protocol, content):
    if type in ["DO", "RH", "HBH", "FH"]:
        
        # Validate the length of content
        stats = psutil.net_if_stats()
        mtu = stats.get(interface).mtu

        if len(content) == 0:
            print("---> The file has empty content. Try again!!!")
            sys.exit(1)
        if len(content) <= (mtu-100):
            num_full_packets = 1
        if len(content) > (mtu-100):
            num_full_packets = floor(len(content) / (mtu-100))
        content_parts = [content[i:i + (mtu-100)] for i in range(0, len(content), (mtu-100))]

        # Generate packets
        if destination_mac is None:
            layer2 = Ether(src=source_mac, dst="33:33:00:00:00:01")
        if destination_mac is not None:
            layer2 = Ether(src=source_mac, dst=destination_mac)
        layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=255)

        factor_main = int(len(content_parts[0]) / 255)
        data_left_main = len(content_parts[-1]) - factor_main * 255
        print("Sending " + str(num_full_packets+1) + " Covert Channel messages to the destination: " + destination_ip)

        pkt_list = []
        for i in range(num_full_packets):
            option1 = HBHOptUnknown(otype=16, optlen=4, optdata=RandString(4))
            num_set = str(i + 1)
            num_set = num_set.ljust(4, '0')
            option2 = HBHOptUnknown(otype=17, optlen=4, optdata=num_set)
            option = [option1, option2]
            index = 0
            for j in range(factor_main):
                option3 = HBHOptUnknown(otype=18 + j, optdata=content_parts[i][index:index + 255])
                index = index + 255
                option.append(option3)
            if data_left_main > 0:
                option3 = HBHOptUnknown(otype=31, optdata=content_parts[i][index:])
                option.append(option3)
            
            if type == "HBH":
                Opt = IPv6ExtHdrHopByHop(options=option)
            if type == "DO":
                Opt = IPv6ExtHdrDestOpt(options=option)
            if type == "RH":
                Opt = IPv6ExtHdrRouting() / IPv6ExtHdrDestOpt(options=option)
            if type == "FH":
                Opt = IPv6ExtHdrFragment(id=12345) / IPv6ExtHdrFragment(id=12345) / IPv6ExtHdrDestOpt(options=option)
            
            if protocol == "ICMPv6":
                packet1 = layer2 / layer3 / Opt / ICMPv6EchoRequest(id=RandShort(), seq=i + 1, data="ABCDEDGHIJKLMNOPQRSTUVWXYZ")
            elif protocol == "IPv6":
                packet1 = layer2 / layer3 / Opt
            elif protocol == "UDP":
                packet1 = layer2 / layer3 / Opt / UDP(dport=10000, sport=20000)
            elif protocol == "TCP":
                packet1 = layer2 / layer3 / Opt / TCP(dport=10000, sport=20000, flags="S")
                
            pkt_list.append(packet1)
            
            sendp(packet1, verbose=False, iface=interface)

        # Generate the last packet
        if num_full_packets > 1:
            factor = int(len(content_parts[-1]) / 255)
            data_left = len(content_parts[-1]) - factor * 255
            option1 = HBHOptUnknown(otype=16, optlen=4, optdata=RandString(4))
            num_set = str(num_full_packets + 1)
            num_set = num_set.ljust(4, '0')
            option2 = HBHOptUnknown(otype=17, optlen=4, optdata=num_set)
            option = [option1, option2]
            index = 0
            if factor == 0:
                option3 = HBHOptUnknown(otype=31, optdata=content_parts[-1])
                option.append(option3)
            else:
                for j in range(factor):
                    option3 = HBHOptUnknown(otype=18 + j, optdata=content_parts[-1][index:index + 255])
                    index = index + 255
                    option.append(option3)
            if data_left > 0:
                option3 = HBHOptUnknown(otype=31, optdata=content_parts[-1][index:])
                option.append(option3)
            if type == "HBH":
                Opt = IPv6ExtHdrHopByHop(options=option)
            if type == "DO":
                Opt = IPv6ExtHdrDestOpt(options=option)
            if type == "RH":
                Opt = IPv6ExtHdrRouting() / IPv6ExtHdrDestOpt(options=option)
            if type == "FH":
                Opt = IPv6ExtHdrFragment(id=12345) / IPv6ExtHdrFragment(id=12345) / IPv6ExtHdrDestOpt(options=option)
            
            if protocol == "ICMPv6":
                packet1 = layer2 / layer3 / Opt / ICMPv6EchoRequest(id=RandShort(), seq=i + 1, data="ABCDEDGHIJKLMNOPQRSTUVWXYZ")
            elif protocol == "IPv6":
                packet1 = layer2 / layer3 / Opt
            elif protocol == "UDP":
                packet1 = layer2 / layer3 / Opt / UDP(dport=10000, sport=20000)
            elif protocol == "TCP":
                packet1 = layer2 / layer3 / Opt / TCP(dport=10000, sport=20000, flags="S")
                
            pkt_list.append(packet1)
            sendp(packet1, verbose=False, iface=interface)
    # sendpfast(pkt_list, mbps=60000, pps=30000, iface=interface)

    if type in ['TC', 'FL', 'NH', 'HL']:
        # Generate packets
        if destination_mac is None:
            layer2 = Ether(src=source_mac, dst="33:33:00:00:00:01")
        if destination_mac is not None:
            layer2 = Ether(src=source_mac, dst=destination_mac)
            
        for letter in content:
            if type == 'TC':
                layer3 = IPv6(src=source_ip, dst=destination_ip, tc=letter)
            if type == 'FL':
                layer3 = IPv6(src=source_ip, dst=destination_ip, fl=letter)
            if type == 'NH':
                layer3 = IPv6(src=source_ip, dst=destination_ip, nh=letter)
            if type == 'HL':
                layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=letter)
            
            if protocol == "ICMPv6":
                packet1 = layer2 / layer3 / ICMPv6EchoRequest(id=RandShort(), seq=33, data="ABCDEDGHIJKLMNOPQRSTUVWXYZ")
            elif protocol == "IPv6":
                packet1 = layer2 / layer3           
            elif protocol == "UDP":
                packet1 = layer2 / layer3 / UDP(dport=10000, sport=20000)
            elif protocol == "TCP":
                packet1 = layer2 / layer3 / TCP(dport=10000, sport=20000, flags="S")            
            sendp(packet1, verbose=False, iface=interface)
            
def sniffing(interface, source_ip, destination_ip):
    # Define our Custom Action function
    packet_counts = Counter()
    mac_list = []

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        if packet[0][1].src == destination_ip and packet[0][1].dst == source_ip and ICMPv6EchoReply in packet:
            key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
            packet_counts.update([key])
            if packet[0].src not in mac_list:
                mac_list.append(packet[0].src)
            print("+ Received Response message number #" + str(sum(packet_counts.values())))
            print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)

    # Setup sniff, filtering for IP traffic to see the result
    build_filter = "ip6 dst %s" % source_ip

    try:
        sniff(iface=interface, filter=build_filter, prn=custom_action, timeout=2.5)
    except KeyboardInterrupt:
        sys.exit(0)
    num_hosts = len(mac_list)
    if num_hosts == 0:
        print("+ No response from destination: " + destination_ip)


def execute_functions(interface, source_mac, destination_mac, source_ip, destination_ip, covert_type, protocol, content):
    p1 = multiprocessing.Process(target=generate, args=[interface, source_mac, destination_mac, source_ip, destination_ip, covert_type, protocol, content])
    p2 = multiprocessing.Process(target=sniffing, args=[interface, source_ip, destination_ip])
    p2.start()
    p1.start()
    p2.join()
    p1.join()


if __name__ == "__main__":
    # Turning off logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    interface, source_mac, destination_mac, source_ip, destination_ip, covert_type, protocol, content = parameter()
    try:
        execute_functions(interface, source_mac, destination_mac, source_ip, destination_ip, covert_type, protocol, content)
    except KeyboardInterrupt:
        sys.exit(0)
