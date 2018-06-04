#!/usr/bin/python

# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from scapy.all import *
import base64
import random

INTF="veth1"

def randomword(max_length):
    length = random.randint(1, max_length)
    return ''.join(random.choice(['f','s','2']) for i in range(length))

def handle_pkt(pkt):
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        id_tup = (src_ip, dst_ip, proto, sport, dport)
        data = pkt[Raw].load
        print ("Received from %s, %s" %(id_tup,data))
        if(src_ip == "10.0.7.23" ):
            for i in range(500):
                print(base64.b64encode(randomword(80)))
            p = Ether(src="11:22:33:44:55:66",dst="00:00:00:23:22:11")/IP(dst=src_ip,src=dst_ip)
            p = p/TCP(dport=sport)/Raw(load=data)
            sendp(p, iface = INTF)

def main():
    sniff(iface = INTF,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
