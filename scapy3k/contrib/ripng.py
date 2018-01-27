#!/usr/bin/env python

# http://trac.secdev.org/scapy/ticket/301

# scapy3k.contrib.description = RIPng
# scapy3k.contrib.status = loads

from scapy3k.packet import *
from scapy3k.fields import *
from scapy3k.layers.inet import UDP
from scapy3k.layers.inet6 import *

class RIPng(Packet):
    name = "RIPng header"
    fields_desc = [
                    ByteEnumField("cmd", 1, {1 : "req", 2 : "resp"}),
                    ByteField("ver", 1),
                    ShortField("null", 0),
            ]

class RIPngEntry(Packet):
    name = "RIPng entry"
    fields_desc = [
                    ConditionalField(IP6Field("prefix", "::"),
                                            lambda pkt: pkt.metric != 255),
                    ConditionalField(IP6Field("nexthop", "::"),
                                            lambda pkt: pkt.metric == 255),
                    ShortField("routetag", 0),
                    ByteField("prefixlen", 0),
                    ByteEnumField("metric", 1, {16 : "Unreach",
                                                255 : "next-hop entry"})
            ]

bind_layers(UDP,        RIPng,          sport=521, dport=521)
bind_layers(RIPng,      RIPngEntry)
bind_layers(RIPngEntry, RIPngEntry)

if __name__ == "__main__":
    from scapy3k.main import interact
    interact(mydict=globals(), mybanner="RIPng")

