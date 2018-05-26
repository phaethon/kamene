# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more informations
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
IPv4 (Internet Protocol v4).
"""

import os
import time
import struct
import re
import socket
from select import select
from collections import defaultdict
from kamene.utils import checksum, is_private_addr
from kamene.layers.l2 import ( BitEnumField,
                              BitField,
                              ByteEnumField,
                              ByteField,
                              ConditionalField,
                              CookedLinux,
                              Dot3,
                              ETH_P_ALL,
                              ETH_P_IP,
                              Emph,
                              Ether,
                              FieldLenField,
                              FieldListField,
                              FlagsField,
                              GRE,
                              Gen,
                              IPField,
                              IP_PROTOS,
                              IncrementalValue,
                              IntAutoMicroTime,
                              IntField,
                              MultiEnumField,
                              Net,
                              NoPayload,
                              Packet,
                              PacketListField,
                              RandInt,
                              RandShort,
                              RandString,
                              RandStringTerm,
                              Raw,
                              SNAP,
                              ShortEnumField,
                              ShortField,
                              SourceIPField,
                              StrField,
                              StrFixedLenField,
                              StrLenField,
                              TCP_SERVICES,
                              UDP_SERVICES,
                              X3BytesField,
                              XByteField,
                              XShortField,
                              bind_layers,
                              colgen,
                              conf,
                              do_graph,
                              getmacbyip,
                              incremental_label,
                              inet_aton,
                              linehexdump,
                              log_runtime,
                              os,
                              random,
                              re,
                              socket,
                              struct,
                              strxor,
                              time,
                              warning)
from kamene.sendrecv import sr, sr1
from kamene.plist import PacketList, SndRcvList
from kamene.automaton import Automaton, ATMT

import kamene.as_resolvers


##################
# IP Tools class #
##################

class IPTools:
    """Add more powers to a class that have a "src" attribute."""

    def whois(self):
        os.system("whois %s" % self.src)

    def ottl(self):
        t = [32, 64, 128, 255] + [self.ttl]
        t.sort()
        return t[t.index(self.ttl) + 1]

    def hops(self):
        return self.ottl() - self.ttl - 1

    def is_priv_addr(self):
        return is_private_addr(self.src)


_ip_options_names = {0: "end_of_list",
                     1: "nop",
                     2: "security",
                     3: "loose_source_route",
                     4: "timestamp",
                     5: "extended_security",
                     6: "commercial_security",
                     7: "record_route",
                     8: "stream_id",
                     9: "strict_source_route",
                     10: "experimental_measurement",
                     11: "mtu_probe",
                     12: "mtu_reply",
                     13: "flow_control",
                     14: "access_control",
                     15: "encode",
                     16: "imi_traffic_descriptor",
                     17: "extended_IP",
                     18: "traceroute",
                     19: "address_extension",
                     20: "router_alert",
                     21: "selective_directed_broadcast_mode",
                     23: "dynamic_packet_state",
                     24: "upstream_multicast_packet",
                     25: "quick_start",
                     30: "rfc4727_experiment",
                     }


class _IPOption_HDR(Packet):
    fields_desc = [BitField("copy_flag", 0, 1),
                   BitEnumField("optclass", 0, 2, {0: "control", 2: "debug"}),
                   BitEnumField("option", 0, 5, _ip_options_names)]


class IPOption(Packet):
    name = "IP Option"
    fields_desc = [_IPOption_HDR,
                   FieldLenField("length", None, fmt="B",  # Only option 0 and 1 have no length and value
                                 length_of="value", adjust=lambda pkt, l:l + 2),
                   StrLenField("value", "", length_from=lambda pkt:pkt.length - 2)]

    def extract_padding(self, p):
        return b"", p

    registered_ip_options = {}

    @classmethod
    def register_variant(cls):
        cls.registered_ip_options[cls.option.default] = cls

    @classmethod
    def dispatch_hook(cls, pkt=None, *args, **kargs):
        if pkt:
            opt = pkt[0] & 0x1f
            if opt in cls.registered_ip_options:
                return cls.registered_ip_options[opt]
        return cls


class IPOption_EOL(IPOption):
    name = "IP Option End of Options List"
    option = 0
    fields_desc = [_IPOption_HDR]


class IPOption_NOP(IPOption):
    name = "IP Option No Operation"
    option = 1
    fields_desc = [_IPOption_HDR]


class IPOption_Security(IPOption):
    name = "IP Option Security"
    copy_flag = 1
    option = 2
    fields_desc = [_IPOption_HDR,
                   ByteField("length", 11),
                   ShortField("security", 0),
                   ShortField("compartment", 0),
                   ShortField("handling_restrictions", 0),
                   StrFixedLenField("transmission_control_code", "xxx", 3),
                   ]


class IPOption_LSRR(IPOption):
    name = "IP Option Loose Source and Record Route"
    copy_flag = 1
    option = 3
    fields_desc = [_IPOption_HDR,
                   FieldLenField("length", None, fmt="B",
                                 length_of="routers", adjust=lambda pkt, l:l + 3),
                   ByteField("pointer", 4),  # 4 is first IP
                   FieldListField("routers", [], IPField("", "0.0.0.0"),
                                  length_from=lambda pkt:pkt.length - 3)
                   ]

    def get_current_router(self):
        return self.routers[self.pointer // 4 - 1]


class IPOption_RR(IPOption_LSRR):
    name = "IP Option Record Route"
    option = 7


class IPOption_SSRR(IPOption_LSRR):
    name = "IP Option Strict Source and Record Route"
    option = 9


class IPOption_Stream_Id(IPOption):
    name = "IP Option Stream ID"
    option = 8
    fields_desc = [_IPOption_HDR,
                   ByteField("length", 4),
                   ShortField("security", 0), ]


class IPOption_MTU_Probe(IPOption):
    name = "IP Option MTU Probe"
    option = 11
    fields_desc = [_IPOption_HDR,
                   ByteField("length", 4),
                   ShortField("mtu", 0), ]


class IPOption_MTU_Reply(IPOption_MTU_Probe):
    name = "IP Option MTU Reply"
    option = 12


class IPOption_Traceroute(IPOption):
    name = "IP Option Traceroute"
    copy_flag = 1
    option = 18
    fields_desc = [_IPOption_HDR,
                   ByteField("length", 12),
                   ShortField("id", 0),
                   ShortField("outbound_hops", 0),
                   ShortField("return_hops", 0),
                   IPField("originator_ip", "0.0.0.0")]


class IPOption_Address_Extension(IPOption):
    name = "IP Option Address Extension"
    copy_flag = 1
    option = 19
    fields_desc = [_IPOption_HDR,
                   ByteField("length", 10),
                   IPField("src_ext", "0.0.0.0"),
                   IPField("dst_ext", "0.0.0.0")]


class IPOption_Router_Alert(IPOption):
    name = "IP Option Router Alert"
    copy_flag = 1
    option = 20
    fields_desc = [_IPOption_HDR,
                   ByteField("length", 4),
                   ShortEnumField("alert", 0, {0: "router_shall_examine_packet"}), ]


class IPOption_SDBM(IPOption):
    name = "IP Option Selective Directed Broadcast Mode"
    copy_flag = 1
    option = 21
    fields_desc = [_IPOption_HDR,
                   FieldLenField("length", None, fmt="B",
                                 length_of="addresses", adjust=lambda pkt, l:l + 2),
                   FieldListField("addresses", [], IPField("", "0.0.0.0"),
                                  length_from=lambda pkt:pkt.length - 2)
                   ]


TCPOptions = (
    {0: ("EOL", None),
     1: ("NOP", None),
     2: ("MSS", "!H"),
     3: ("WScale", "!B"),
     4: ("SAckOK", None),
     5: ("SAck", "!"),
     8: ("Timestamp", "!II"),
     14: ("AltChkSum", "!BH"),
     15: ("AltChkSumOpt", None),
     25: ("Mood", "!p")
     },
    {"EOL": 0,
     "NOP": 1,
     "MSS": 2,
     "WScale": 3,
     "SAckOK": 4,
     "SAck": 5,
     "Timestamp": 8,
     "AltChkSum": 14,
     "AltChkSumOpt": 15,
     "Mood": 25
     })


class TCPOptionsField(StrField):
    islist = 1

    def getfield(self, pkt, s):
        opsz = (pkt.dataofs - 5) * 4
        if opsz < 0:
            warning("bad dataofs (%i). Assuming dataofs=5" % pkt.dataofs)
            opsz = 0
        return s[opsz:], self.m2i(pkt, s[:opsz])

    def m2i(self, pkt, x):
        opt = []
        while x:
            onum = x[0]
            if onum == 0:
                opt.append(("EOL", None))
                x = x[1:]
                break
            if onum == 1:
                opt.append(("NOP", None))
                x = x[1:]
                continue
            olen = x[1]
            if olen < 2:
                warning("Malformed TCP option (announced length is %i)" % olen)
                olen = 2
            oval = x[2:olen]
            if onum in TCPOptions[0]:
                oname, ofmt = TCPOptions[0][onum]
                if onum == 5:  # SAck
                    ofmt += "%iI" % (len(oval) // 4)
                if ofmt and struct.calcsize(ofmt) == len(oval):
                    oval = struct.unpack(ofmt, oval)
                    if len(oval) == 1:
                        oval = oval[0]
                opt.append((oname, oval))
            else:
                opt.append((onum, oval))
            x = x[olen:]
        return opt

    def i2m(self, pkt, x):
        opt = b""
        for oname, oval in x:
            if type(oname) is str:
                if oname == "NOP":
                    opt += b"\x01"
                    continue
                elif oname == "EOL":
                    opt += b"\x00"
                    continue
                elif oname in TCPOptions[1]:
                    onum = TCPOptions[1][oname]
                    ofmt = TCPOptions[0][onum][1]
                    if onum == 5:  # SAck
                        ofmt += "%iI" % len(oval)
                    if ofmt is not None and (type(oval) is not str or "s" in ofmt):
                        if type(oval) is not tuple:
                            oval = (oval,)
                        oval = struct.pack(ofmt, *oval)
                else:
                    warning("option [%s] unknown. Skipped." % oname)
                    continue
            else:
                onum = oname
                if type(oval) is not bytes:
                    warning("option [%i] is not of type bytes." % onum)
                    continue
            opt += bytes([(onum), (2 + len(oval))]) + oval
        return opt + b"\x00" * (3 - ((len(opt) + 3) % 4))

    def randval(self):
        return []  # XXX


class ICMPTimeStampField(IntField):
    re_hmsm = re.compile("([0-2]?[0-9])[Hh:](([0-5]?[0-9])([Mm:]([0-5]?[0-9])([sS:.]([0-9]{0,3}))?)?)?$")

    def i2repr(self, pkt, val):
        if val is None:
            return "--"
        else:
            sec, milli = divmod(val, 1000)
            min, sec = divmod(sec, 60)
            hour, min = divmod(min, 60)
            return "%d:%d:%d.%d" % (hour, min, sec, int(milli))

    def any2i(self, pkt, val):
        if type(val) is str:
            hmsms = self.re_hmsm.match(val)
            if hmsms:
                h, _, m, _, s, _, ms = hmsms = hmsms.groups()
                ms = int(((ms or "") + "000")[:3])
                val = ((int(h) * 60 + int(m or 0)) * 60 + int(s or 0)) * 1000 + ms
            else:
                val = 0
        elif val is None:
            val = int((time.time() % (24 * 60 * 60)) * 1000)
        return val


class IP(Packet, IPTools):
    name = "IP"
    fields_desc = [BitField("version", 4, 4),
                   BitField("ihl", None, 4),
                   XByteField("tos", 0),
                   ShortField("len", None),
                   ShortField("id", 1),
                   FlagsField("flags", 0, 3, ["MF", "DF", "evil"]),
                   BitField("frag", 0, 13),
                   ByteField("ttl", 64),
                   ByteEnumField("proto", 0, IP_PROTOS),
                   XShortField("chksum", None),
                   #IPField("src", "127.0.0.1"),
                   Emph(SourceIPField("src", "dst")),
                   Emph(IPField("dst", "127.0.0.1")),
                   PacketListField("options", [], IPOption, length_from=lambda p:p.ihl * 4 - 20)]

    def post_build(self, p, pay):
        ihl = self.ihl
        p += b"\0" * ((-len(p)) % 4)  # pad IP options if needed
        if ihl is None:
            ihl = len(p) // 4
            p = bytes([((self.version & 0xf) << 4) | ihl & 0x0f]) + p[1:]
        if self.len is None:
            l = len(p) + len(pay)
            p = p[:2] + struct.pack("!H", l) + p[4:]
        if self.chksum is None:
            ck = checksum(p)
            p = p[:10] + bytes([ck >> 8]) + bytes([ck & 0xff]) + p[12:]
        return p + pay

    def extract_padding(self, s):
        l = self.len - (self.ihl << 2)
        return s[:l], s[l:]

    def send(self, s, slp=0):
        for p in self:
            try:
                s.sendto(bytes(p), (p.dst, 0))
            except socket.error as msg:
                log_runtime.error(msg)
            if slp:
                time.sleep(slp)

    def route(self):
        dst = self.dst
        if isinstance(dst, Gen):
            dst = next(iter(dst))
        return conf.route.route(dst)

    def hashret(self):
        if ((self.proto == socket.IPPROTO_ICMP)
            and (isinstance(self.payload, ICMP))
                and (self.payload.type in [3, 4, 5, 11, 12])):
            return self.payload.payload.hashret()
        else:
            if conf.checkIPsrc and conf.checkIPaddr:
                return strxor(inet_aton(self.src), inet_aton(self.dst)) + struct.pack("B", self.proto) + self.payload.hashret()
            else:
                return struct.pack("B", self.proto) + self.payload.hashret()

    def answers(self, other):
        if not isinstance(other, IP):
            return 0
        if conf.checkIPaddr and (self.dst != other.src):
            return 0
        if ((self.proto == socket.IPPROTO_ICMP) and
            (isinstance(self.payload, ICMP)) and
                (self.payload.type in [3, 4, 5, 11, 12])):
            # ICMP error message
            return self.payload.payload.answers(other)

        else:
            if ((conf.checkIPaddr and (self.src != other.dst)) or
                    (self.proto != other.proto)):
                return 0
            return self.payload.answers(other.payload)

    def mysummary(self):
        s = self.sprintf("%IP.src% > %IP.dst% %IP.proto%")
        if self.frag:
            s += " frag:%i" % self.frag
        return s

    def fragment(self, fragsize=1480):
        """Fragment IP datagrams"""
        fragsize = (fragsize + 7) // 8 * 8
        lst = []
        fnb = 0
        fl = self
        while fl.underlayer is not None:
            fnb += 1
            fl = fl.underlayer

        for p in fl:
            s = bytes(p[fnb].payload)
            nb = (len(s) + fragsize - 1) // fragsize
            for i in range(nb):
                q = p.copy()
                del q[fnb].payload
                del q[fnb].chksum
                del q[fnb].len
                if i == nb - 1:
                    q[IP].flags &= ~1
                else:
                    q[IP].flags |= 1
                q[IP].frag = i * fragsize // 8
                r = conf.raw_layer(load=s[i * fragsize:(i + 1) * fragsize])
                r.overload_fields = p[IP].payload.overload_fields.copy()
                q.add_payload(r)
                lst.append(q)
        return lst


class TCP(Packet):
    name = "TCP"
    fields_desc = [ShortEnumField("sport", 20, TCP_SERVICES),
                   ShortEnumField("dport", 80, TCP_SERVICES),
                   IntField("seq", 0),
                   IntField("ack", 0),
                   BitField("dataofs", None, 4),
                   BitField("reserved", 0, 4),
                   FlagsField("flags", 0x2, 8, "FSRPAUEC"),
                   ShortField("window", 8192),
                   XShortField("chksum", None),
                   ShortField("urgptr", 0),
                   TCPOptionsField("options", {})]

    def post_build(self, p, pay):
        p += pay
        dataofs = self.dataofs
        if dataofs is None:
            dataofs = 5 + ((len(self.get_field("options").i2m(self, self.options)) + 3) // 4)
            p = p[:12] + bytes([(dataofs << 4) | (p[12]) & 0x0f]) + p[13:]
        if self.chksum is None:
            if isinstance(self.underlayer, IP):
                if self.underlayer.len is not None:
                    ln = self.underlayer.len - 20
                else:
                    ln = len(p)
                psdhdr = struct.pack("!4s4sHH",
                                     inet_aton(self.underlayer.src),
                                     inet_aton(self.underlayer.dst),
                                     self.underlayer.proto,
                                     ln)
                ck = checksum(psdhdr + p)
                p = p[:16] + struct.pack("!H", ck) + p[18:]
            elif conf.ipv6_enabled and isinstance(self.underlayer, kamene.layers.inet6.IPv6) or isinstance(self.underlayer, kamene.layers.inet6._IPv6ExtHdr):
                ck = kamene.layers.inet6.in6_chksum(socket.IPPROTO_TCP, self.underlayer, p)
                p = p[:16] + struct.pack("!H", ck) + p[18:]
            else:
                warning("No IP underlayer to compute checksum. Leaving null.")
        return p

    def hashret(self):
        if conf.checkIPsrc:
            return struct.pack("H", self.sport ^ self.dport) + self.payload.hashret()
        else:
            return self.payload.hashret()

    def answers(self, other):
        if not isinstance(other, TCP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.dport) and
                    (self.dport == other.sport)):
                return 0
        if abs(other.seq - self.ack) > 2 + len(other.payload):
            return 0
        return 1

    def mysummary(self):
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("TCP %IP.src%:%TCP.sport% > %IP.dst%:%TCP.dport% %TCP.flags%")
        elif conf.ipv6_enabled and isinstance(self.underlayer, kamene.layers.inet6.IPv6):
            return self.underlayer.sprintf("TCP %IPv6.src%:%TCP.sport% > %IPv6.dst%:%TCP.dport% %TCP.flags%")
        else:
            return self.sprintf("TCP %TCP.sport% > %TCP.dport% %TCP.flags%")


class UDP(Packet):
    name = "UDP"
    fields_desc = [ShortEnumField("sport", 53, UDP_SERVICES),
                   ShortEnumField("dport", 53, UDP_SERVICES),
                   ShortField("len", None),
                   XShortField("chksum", None), ]

    def post_build(self, p, pay):
        p += pay
        l = self.len
        if l is None:
            l = len(p)
            p = p[:4] + struct.pack("!H", l) + p[6:]
        if self.chksum is None:
            if isinstance(self.underlayer, IP):
                if self.underlayer.len is not None:
                    ln = self.underlayer.len - 20
                else:
                    ln = len(p)
                psdhdr = struct.pack("!4s4sHH",
                                     inet_aton(self.underlayer.src),
                                     inet_aton(self.underlayer.dst),
                                     self.underlayer.proto,
                                     ln)
                ck = checksum(psdhdr + p)
                p = p[:6] + struct.pack("!H", ck) + p[8:]
            elif isinstance(self.underlayer, kamene.layers.inet6.IPv6) or isinstance(self.underlayer, kamene.layers.inet6._IPv6ExtHdr):
                ck = kamene.layers.inet6.in6_chksum(socket.IPPROTO_UDP, self.underlayer, p)
                p = p[:6] + struct.pack("!H", ck) + p[8:]
            else:
                warning("No IP underlayer to compute checksum. Leaving null.")
        return p

    def extract_padding(self, s):
        l = self.len - 8
        return s[:l], s[l:]

    def hashret(self):
        return self.payload.hashret()

    def answers(self, other):
        if not isinstance(other, UDP):
            return 0
        if conf.checkIPsrc:
            if self.dport != other.sport:
                return 0
        return self.payload.answers(other.payload)

    def mysummary(self):
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("UDP %IP.src%:%UDP.sport% > %IP.dst%:%UDP.dport%")
        elif isinstance(self.underlayer, kamene.layers.inet6.IPv6):
            return self.underlayer.sprintf("UDP %IPv6.src%:%UDP.sport% > %IPv6.dst%:%UDP.dport%")
        else:
            return self.sprintf("UDP %UDP.sport% > %UDP.dport%")


icmptypes = {0: "echo-reply",
             3: "dest-unreach",
             4: "source-quench",
             5: "redirect",
             8: "echo-request",
             9: "router-advertisement",
             10: "router-solicitation",
             11: "time-exceeded",
             12: "parameter-problem",
             13: "timestamp-request",
             14: "timestamp-reply",
             15: "information-request",
             16: "information-response",
             17: "address-mask-request",
             18: "address-mask-reply"}

icmpcodes = {3: {0: "network-unreachable",
                 1: "host-unreachable",
                 2: "protocol-unreachable",
                 3: "port-unreachable",
                 4: "fragmentation-needed",
                 5: "source-route-failed",
                 6: "network-unknown",
                 7: "host-unknown",
                 9: "network-prohibited",
                 10: "host-prohibited",
                 11: "TOS-network-unreachable",
                 12: "TOS-host-unreachable",
                 13: "communication-prohibited",
                 14: "host-precedence-violation",
                 15: "precedence-cutoff", },
             5: {0: "network-redirect",
                 1: "host-redirect",
                 2: "TOS-network-redirect",
                 3: "TOS-host-redirect", },
             11: {0: "ttl-zero-during-transit",
                  1: "ttl-zero-during-reassembly", },
             12: {0: "ip-header-bad",
                  1: "required-option-missing", }, }


class ICMP(Packet):
    name = "ICMP"
    fields_desc = [ByteEnumField("type", 8, icmptypes),
                   MultiEnumField("code", 0, icmpcodes, depends_on=lambda pkt:pkt.type, fmt="B"),
                   XShortField("chksum", None),
                   ConditionalField(XShortField("id", 0), lambda pkt:pkt.type in [0, 8, 13, 14, 15, 16, 17, 18]),
                   ConditionalField(XShortField("seq", 0), lambda pkt:pkt.type in [0, 8, 13, 14, 15, 16, 17, 18]),
                   ConditionalField(ICMPTimeStampField("ts_ori", None), lambda pkt:pkt.type in [13, 14]),
                   ConditionalField(ICMPTimeStampField("ts_rx", None), lambda pkt:pkt.type in [13, 14]),
                   ConditionalField(ICMPTimeStampField("ts_tx", None), lambda pkt:pkt.type in [13, 14]),
                   ConditionalField(IPField("gw", "0.0.0.0"), lambda pkt:pkt.type == 5),
                   ConditionalField(ByteField("ptr", 0), lambda pkt:pkt.type == 12),
                   ConditionalField(X3BytesField("reserved", 0), lambda pkt:pkt.type == 12),
                   ConditionalField(IPField("addr_mask", "0.0.0.0"), lambda pkt:pkt.type in [17, 18]),
                   ConditionalField(IntField("unused", 0), lambda pkt:pkt.type not in [0, 5, 8, 12, 13, 14, 15, 16, 17, 18]),

                   ]

    def post_build(self, p, pay):
        p += pay
        if self.chksum is None:
            ck = checksum(p)
            p = p[:2] + bytes([ck >> 8, ck & 0xff]) + p[4:]
        return p

    def hashret(self):
        if self.type in [0, 8, 13, 14, 15, 16, 17, 18]:
            return struct.pack("HH", self.id, self.seq) + self.payload.hashret()
        return self.payload.hashret()

    def answers(self, other):
        if not isinstance(other, ICMP):
            return 0
        if ((other.type, self.type) in [(8, 0), (13, 14), (15, 16), (17, 18)] and
            self.id == other.id and
                self.seq == other.seq):
            return 1
        return 0

    def guess_payload_class(self, payload):
        if self.type in [3, 4, 5, 11, 12]:
            return IPerror
        else:
            return None

    def mysummary(self):
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("ICMP %IP.src% > %IP.dst% %ICMP.type% %ICMP.code%")
        else:
            return self.sprintf("ICMP %ICMP.type% %ICMP.code%")


class IPerror(IP):
    name = "IP in ICMP"

    def answers(self, other):
        if not isinstance(other, IP):
            return 0
        if not (((conf.checkIPsrc == 0) or (self.dst == other.dst)) and
                (self.src == other.src) and
                (((conf.checkIPID == 0)
                  or (self.id == other.id)
                  or (conf.checkIPID == 1 and self.id == socket.htons(other.id)))) and
                (self.proto == other.proto)):
            return 0
        return self.payload.answers(other.payload)

    def mysummary(self):
        return Packet.mysummary(self)


class TCPerror(TCP):
# Better fix to be found for building and parsing TCPerror inside ICMP destination unreachable. With this at least the test suite passes
    fields_desc = [ShortEnumField("sport", 20, TCP_SERVICES),
                   ShortEnumField("dport", 80, TCP_SERVICES),
                   IntField("seq", 0),
                   IntField("ack", 0),
                   BitField("dataofs", None, 4),
                   BitField("reserved", 0, 4),
                   FlagsField("flags", 0x2, 8, "FSRPAUEC"),
                   ShortField("window", 8192),
                   XShortField("chksum", None),
                   ShortField("urgptr", 0),
                   TCPOptionsField("options", {})]
    name = "TCP in ICMP"

    def post_build(self, p, pay):
        p += pay
        return p

    def answers(self, other):
        if not isinstance(other, TCP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.sport) and
                    (self.dport == other.dport)):
                return 0
        if conf.check_TCPerror_seqack:
            if self.seq is not None:
                if self.seq != other.seq:
                    return 0
            if self.ack is not None:
                if self.ack != other.ack:
                    return 0
        return 1

    def mysummary(self):
        return Packet.mysummary(self)


class UDPerror(UDP):
    name = "UDP in ICMP"

    def answers(self, other):
        if not isinstance(other, UDP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.sport) and
                    (self.dport == other.dport)):
                return 0
        return 1

    def mysummary(self):
        return Packet.mysummary(self)


class ICMPerror(ICMP):
    name = "ICMP in ICMP"

    def answers(self, other):
        if not isinstance(other, ICMP):
            return 0
        if not ((self.type == other.type) and
                (self.code == other.code)):
            return 0
        if self.code in [0, 8, 13, 14, 17, 18]:
            if (self.id == other.id and
                    self.seq == other.seq):
                return 1
            else:
                return 0
        else:
            return 1

    def mysummary(self):
        return Packet.mysummary(self)


bind_layers(Ether, IP, type=2048)
bind_layers(CookedLinux, IP, proto=2048)
bind_layers(GRE, IP, proto=2048)
bind_layers(SNAP, IP, code=2048)
bind_layers(IPerror, IPerror, frag=0, proto=4)
bind_layers(IPerror, ICMPerror, frag=0, proto=1)
bind_layers(IPerror, TCPerror, frag=0, proto=6)
bind_layers(IPerror, UDPerror, frag=0, proto=17)
bind_layers(IP, IP, frag=0, proto=4)
bind_layers(IP, ICMP, frag=0, proto=1)
bind_layers(IP, TCP, frag=0, proto=6)
bind_layers(IP, UDP, frag=0, proto=17)
bind_layers(IP, GRE, frag=0, proto=47)

conf.l2types.register(101, IP)
conf.l2types.register_num2layer(12, IP)

conf.l3types.register(ETH_P_IP, IP)
conf.l3types.register_num2layer(ETH_P_ALL, IP)


conf.neighbor.register_l3(Ether, IP, lambda l2, l3: getmacbyip(l3.dst))
conf.neighbor.register_l3(Dot3, IP, lambda l2, l3: getmacbyip(l3.dst))


#################
# Fragmentation #
#################

@conf.commands.register
def fragment(pkt, fragsize=1480):
    """Fragment a big IP datagram"""
    fragsize = (fragsize + 7) // 8 * 8
    lst = []
    for p in pkt:
        s = bytes(p[IP].payload)
        nb = (len(s) + fragsize - 1) // fragsize
        for i in range(nb):
            q = p.copy()
            del q[IP].payload
            del q[IP].chksum
            del q[IP].len
            if i == nb - 1:
                q[IP].flags &= ~1
            else:
                q[IP].flags |= 1
            q[IP].frag = i * fragsize // 8
            r = conf.raw_layer(load=s[i * fragsize:(i + 1) * fragsize])
            r.overload_fields = p[IP].payload.overload_fields.copy()
            q.add_payload(r)
            lst.append(q)
    return lst


def overlap_frag(p, overlap, fragsize=8, overlap_fragsize=None):
    if overlap_fragsize is None:
        overlap_fragsize = fragsize
    q = p.copy()
    del q[IP].payload
    q[IP].add_payload(overlap)

    qfrag = fragment(q, overlap_fragsize)
    qfrag[-1][IP].flags |= 1
    return qfrag + fragment(p, fragsize)


@conf.commands.register
def defrag(plist):
    """defrag(plist) -> ([not fragmented], [defragmented],
                  [ [bad fragments], [bad fragments], ... ])"""
    frags = defaultdict(PacketList)
    nofrag = PacketList()
    for p in plist:
        ip = p[IP]
        if IP not in p:
            nofrag.append(p)
            continue
        if ip.frag == 0 and ip.flags & 1 == 0:
            nofrag.append(p)
            continue
        uniq = (ip.id, ip.src, ip.dst, ip.proto)
        frags[uniq].append(p)
    defrag = []
    missfrag = []
    for lst in frags.values():
        lst.sort(key=lambda x: x.frag)
        p = lst[0]
        lastp = lst[-1]
        if p.frag > 0 or lastp.flags & 1 != 0:  # first or last fragment missing
            missfrag.append(lst)
            continue
        p = p.copy()
        if conf.padding_layer in p:
            del p[conf.padding_layer].underlayer.payload
        ip = p[IP]
        if ip.len is None or ip.ihl is None:
            clen = len(ip.payload)
        else:
            clen = ip.len - (ip.ihl << 2)
        txt = conf.raw_layer()
        for q in lst[1:]:
            if clen != q.frag << 3:  # Wrong fragmentation offset
                if clen > q.frag << 3:
                    warning("Fragment overlap (%i > %i) %r || %r ||  %r" % (clen, q.frag << 3, p, txt, q))
                missfrag.append(lst)
                break
            if q[IP].len is None or q[IP].ihl is None:
                clen += len(q[IP].payload)
            else:
                clen += q[IP].len - (q[IP].ihl << 2)
            if conf.padding_layer in q:
                del q[conf.padding_layer].underlayer.payload
            txt.add_payload(q[IP].payload.copy())
        else:
            ip.flags &= ~1  # !MF
            del ip.chksum
            del ip.len
            p = p / txt
            defrag.append(p)
    defrag2 = PacketList()
    for p in defrag:
        defrag2.append(p.__class__(bytes(p)))
    return nofrag, defrag2, missfrag


@conf.commands.register
def defragment(plist):
    """defragment(plist) -> plist defragmented as much as possible """
    frags = defaultdict(lambda: [])
    final = []

    pos = 0
    for p in plist:
        p._defrag_pos = pos
        pos += 1
        if IP in p:
            ip = p[IP]
            if ip.frag != 0 or ip.flags & 1:
                ip = p[IP]
                uniq = (ip.id, ip.src, ip.dst, ip.proto)
                frags[uniq].append(p)
                continue
        final.append(p)

    defrag = []
    missfrag = []
    for lst in frags.values():
        lst.sort(key=lambda x: x.frag)
        p = lst[0]
        lastp = lst[-1]
        if p.frag > 0 or lastp.flags & 1 != 0:  # first or last fragment missing
            missfrag += lst
            continue
        p = p.copy()
        if conf.padding_layer in p:
            del p[conf.padding_layer].underlayer.payload
        ip = p[IP]
        if ip.len is None or ip.ihl is None:
            clen = len(ip.payload)
        else:
            clen = ip.len - (ip.ihl << 2)
        txt = conf.raw_layer()
        for q in lst[1:]:
            if clen != q.frag << 3:  # Wrong fragmentation offset
                if clen > q.frag << 3:
                    warning("Fragment overlap (%i > %i) %r || %r ||  %r" % (clen, q.frag << 3, p, txt, q))
                missfrag += lst
                break
            if q[IP].len is None or q[IP].ihl is None:
                clen += len(q[IP].payload)
            else:
                clen += q[IP].len - (q[IP].ihl << 2)
            if conf.padding_layer in q:
                del q[conf.padding_layer].underlayer.payload
            txt.add_payload(q[IP].payload.copy())
        else:
            ip.flags &= ~1  # !MF
            del ip.chksum
            del ip.len
            p = p / txt
            p._defrag_pos = max(x._defrag_pos for x in lst)
            defrag.append(p)
    defrag2 = []
    for p in defrag:
        q = p.__class__(bytes(p))
        q._defrag_pos = p._defrag_pos
        defrag2.append(q)
    final += defrag2
    final += missfrag
    final.sort(key=lambda x: x._defrag_pos)
    for p in final:
        del p._defrag_pos

    if hasattr(plist, "listname"):
        name = "Defragmented %s" % plist.listname
    else:
        name = "Defragmented"

    return PacketList(final, name=name)


# Add timeskew_graph() method to PacketList
def _packetlist_timeskew_graph(self, ip, **kargs):
    """Tries to graph the timeskew between the timestamps and real time for a given ip"""
    res = map(lambda x: self._elt2pkt(x), self.res)
    b = filter(lambda x: x.haslayer(IP) and x.getlayer(IP).src == ip and x.haslayer(TCP), res)
    c = []
    for p in b:
        opts = p.getlayer(TCP).options
        for o in opts:
            if o[0] == "Timestamp":
                c.append((p.time, o[1][0]))
    if not c:
        warning("No timestamps found in packet list")
        return
    # d = map(lambda (x,y): (x%2000,((x-c[0][0])-((y-c[0][1])/1000.0))),c)
    d = map(lambda a: (a[0] % 2000, ((a[0] - c[0][0]) - ((a[1] - c[0][1]) / 1000.0))), c)
    return plt.plot(d, **kargs)

#PacketList.timeskew_graph = types.MethodType(_packetlist_timeskew_graph, None)


# Create a new packet list
class TracerouteResult(SndRcvList):

    def __init__(self, res=None, name="Traceroute", stats=None):
        PacketList.__init__(self, res, name, stats, vector_index=1)
        self.graphdef = None
        self.graphASres = 0
        self.padding = 0
        self.hloc = None
        self.nloc = None

    def show(self):
        # return self.make_table(lambda (s,r): (s.sprintf("%IP.dst%:{TCP:tcp%ir,TCP.dport%}{UDP:udp%ir,UDP.dport%}{ICMP:ICMP}"),
        return self.make_table(lambda s, r: (s.sprintf("%IP.dst%:{TCP:tcp%ir,TCP.dport%}{UDP:udp%ir,UDP.dport%}{ICMP:ICMP}"),
                                             s.ttl,
                                             r.sprintf("%-15s,IP.src% {TCP:%TCP.flags%}{ICMP:%ir,ICMP.type%}")))

    def get_trace(self):
        raw_trace = {}
        for s, r in self.res:
            if IP not in s:
                continue
            d = s[IP].dst
            if d not in raw_trace:
                raw_trace[d] = {}
            raw_trace[d][s[IP].ttl] = r[IP].src, ICMP not in r

        trace = {}
        for k in raw_trace.keys():
            m = [x for x in raw_trace[k].keys() if raw_trace[k][x][1]]
            if not m:
                trace[k] = raw_trace[k]
            else:
                m = min(m)
                trace[k] = {i: raw_trace[k][i] for i in raw_trace[k].keys() if not raw_trace[k][i][1] or i <= m}

        return trace

    def trace3D(self):
        """Give a 3D representation of the traceroute.
        right button: rotate the scene
        middle button: zoom
        left button: move the scene
        left button on a ball: toggle IP displaying
        ctrl-left button on a ball: scan ports 21,22,23,25,80 and 443 and display the result"""
        trace = self.get_trace()
        import visual

        class IPsphere(visual.sphere):
            def __init__(self, ip, **kargs):
                visual.sphere.__init__(self, **kargs)
                self.ip = ip
                self.label = None
                self.setlabel(self.ip)

            def setlabel(self, txt, visible=None):
                if self.label is not None:
                    if visible is None:
                        visible = self.label.visible
                    self.label.visible = 0
                elif visible is None:
                    visible = 0
                self.label = visual.label(text=txt, pos=self.pos, space=self.radius, xoffset=10, yoffset=20, visible=visible)

            def action(self):
                self.label.visible ^= 1

        visual.scene = visual.display()
        visual.scene.exit = True
        start = visual.box()
        rings = {}
        tr3d = {}
        for i in trace:
            tr = trace[i]
            tr3d[i] = []
            ttl = tr.keys()
            for t in range(1, max(ttl) + 1):
                if t not in rings:
                    rings[t] = []
                if t in tr:
                    if tr[t] not in rings[t]:
                        rings[t].append(tr[t])
                    tr3d[i].append(rings[t].index(tr[t]))
                else:
                    rings[t].append(("unk", -1))
                    tr3d[i].append(len(rings[t]) - 1)
        for t in rings:
            r = rings[t]
            l = len(r)
            for i in range(l):
                if r[i][1] == -1:
                    col = (0.75, 0.75, 0.75)
                elif r[i][1]:
                    col = visual.color.green
                else:
                    col = visual.color.blue

                s = IPsphere(pos=((l - 1) * visual.cos(2 * i * visual.pi / l), (l - 1) * visual.sin(2 * i * visual.pi / l), 2 * t),
                             ip=r[i][0],
                             color=col)
                for trlst in tr3d.values():
                    if t <= len(trlst):
                        if trlst[t - 1] == i:
                            trlst[t - 1] = s
        forecol = colgen(0.625, 0.4375, 0.25, 0.125)
        for trlst in tr3d.values():
            col = next(forecol)
            start = (0, 0, 0)
            for ip in trlst:
                visual.cylinder(pos=start, axis=ip.pos - start, color=col, radius=0.2)
                start = ip.pos

        movcenter = None
        while 1:
            visual.rate(50)
            if visual.scene.kb.keys:
                k = visual.scene.kb.getkey()
                if k == "esc" or k == "q":
                    break
            if visual.scene.mouse.events:
                ev = visual.scene.mouse.getevent()
                if ev.press == "left":
                    o = ev.pick
                    if o:
                        if ev.ctrl:
                            if o.ip == "unk":
                                continue
                            savcolor = o.color
                            o.color = (1, 0, 0)
                            a, _ = sr(IP(dst=o.ip) / TCP(dport=[21, 22, 23, 25, 80, 443]), timeout=2)
                            o.color = savcolor
                            if len(a) == 0:
                                txt = "%s:\nno results" % o.ip
                            else:
                                txt = "%s:\n" % o.ip
                                for s, r in a:
                                    txt += r.sprintf("{TCP:%IP.src%:%TCP.sport% %TCP.flags%}{TCPerror:%IPerror.dst%:%TCPerror.dport% %IP.src% %ir,ICMP.type%}\n")
                            o.setlabel(txt, visible=1)
                        else:
                            if hasattr(o, "action"):
                                o.action()
                elif ev.drag == "left":
                    movcenter = ev.pos
                elif ev.drop == "left":
                    movcenter = None
            if movcenter:
                visual.scene.center -= visual.scene.mouse.pos - movcenter
                movcenter = visual.scene.mouse.pos

# # world_trace needs to be reimplemented as gnuplot dependency is removed
#    def world_trace(self):
#        from modules.geo import locate_ip
#        ips = {}
#        rt = {}
#        ports_done = {}
#        for s,r in self.res:
#            ips[r.src] = None
#            if s.haslayer(TCP) or s.haslayer(UDP):
#                trace_id = (s.src,s.dst,s.proto,s.dport)
#            elif s.haslayer(ICMP):
#                trace_id = (s.src,s.dst,s.proto,s.type)
#            else:
#                trace_id = (s.src,s.dst,s.proto,0)
#            trace = rt.get(trace_id,{})
#            if not r.haslayer(ICMP) or r.type != 11:
#                if trace_id in ports_done:
#                    continue
#                ports_done[trace_id] = None
#            trace[s.ttl] = r.src
#            rt[trace_id] = trace
#
#        trt = {}
#        for trace_id in rt:
#            trace = rt[trace_id]
#            loctrace = []
#            for i in range(max(trace.keys())):
#                ip = trace.get(i,None)
#                if ip is None:
#                    continue
#                loc = locate_ip(ip)
#                if loc is None:
#                    continue
# #               loctrace.append((ip,loc)) # no labels yet
#                loctrace.append(loc)
#            if loctrace:
#                trt[trace_id] = loctrace
#
#        tr = map(lambda x: Gnuplot.Data(x,with_="lines"), trt.values())
#        g = Gnuplot.Gnuplot()
#        world = Gnuplot.File(conf.gnuplot_world,with_="lines")
#        g.plot(world,*tr)
#        return g

    def make_graph(self, ASres=None, padding=0):
        if ASres is None:
            ASres = conf.AS_resolver
        self.graphASres = ASres
        self.graphpadding = padding
        ips = {}
        rt = {}
        ports = {}
        ports_done = {}
        for s, r in self.res:
            r = r.getlayer(IP) or (conf.ipv6_enabled and r[kamene.layers.inet6.IPv6]) or r
            s = s.getlayer(IP) or (conf.ipv6_enabled and s[kamene.layers.inet6.IPv6]) or s
            ips[r.src] = None
            if TCP in s:
                trace_id = (s.src, s.dst, 6, s.dport)
            elif UDP in s:
                trace_id = (s.src, s.dst, 17, s.dport)
            elif ICMP in s:
                trace_id = (s.src, s.dst, 1, s.type)
            else:
                trace_id = (s.src, s.dst, s.proto, 0)
            trace = rt.get(trace_id, {})
            ttl = conf.ipv6_enabled and kamene.layers.inet6.IPv6 in s and s.hlim or s.ttl
            if not (ICMP in r and r[ICMP].type == 11) and not (conf.ipv6_enabled and kamene.layers.inet6.IPv6 in r and kamene.layers.inet6.ICMPv6TimeExceeded in r):
                if trace_id in ports_done:
                    continue
                ports_done[trace_id] = None
                p = ports.get(r.src, [])
                if TCP in r:
                    p.append(r.sprintf("<T%ir,TCP.sport%> %TCP.sport% %TCP.flags%"))
                    trace[ttl] = r.sprintf('"%r,src%":T%ir,TCP.sport%')
                elif UDP in r:
                    p.append(r.sprintf("<U%ir,UDP.sport%> %UDP.sport%"))
                    trace[ttl] = r.sprintf('"%r,src%":U%ir,UDP.sport%')
                elif ICMP in r:
                    p.append(r.sprintf("<I%ir,ICMP.type%> ICMP %ICMP.type%"))
                    trace[ttl] = r.sprintf('"%r,src%":I%ir,ICMP.type%')
                else:
                    p.append(r.sprintf("{IP:<P%ir,proto%> IP %proto%}{IPv6:<P%ir,nh%> IPv6 %nh%}"))
                    trace[ttl] = r.sprintf('"%r,src%":{IP:P%ir,proto%}{IPv6:P%ir,nh%}')
                ports[r.src] = p
            else:
                trace[ttl] = r.sprintf('"%r,src%"')
            rt[trace_id] = trace

        # Fill holes with unk%i nodes
        unknown_label = incremental_label("unk%i")
        blackholes = []
        bhip = {}
        for rtk in rt:
            trace = rt[rtk]
            k = trace.keys()
            for n in range(min(k), max(k)):
                if not n in trace:
                    trace[n] = next(unknown_label)
            if not rtk in ports_done:
                if rtk[2] == 1:  # ICMP
                    bh = "%s %i/icmp" % (rtk[1], rtk[3])
                elif rtk[2] == 6:  # TCP
                    bh = "%s %i/tcp" % (rtk[1], rtk[3])
                elif rtk[2] == 17:  # UDP
                    bh = '%s %i/udp' % (rtk[1], rtk[3])
                else:
                    bh = '%s %i/proto' % (rtk[1], rtk[2])
                ips[bh] = None
                bhip[rtk[1]] = bh
                bh = '"%s"' % bh
                trace[max(k) + 1] = bh
                blackholes.append(bh)

        # Find AS numbers
        ASN_query_list = dict.fromkeys(map(lambda x: x.rsplit(" ", 1)[0], ips)).keys()
        if ASres is None:
            ASNlist = []
        else:
            ASNlist = ASres.resolve(*ASN_query_list)

        ASNs = {}
        ASDs = {}
        for ip, asn, desc, in ASNlist:
            if asn is None:
                continue
            iplist = ASNs.get(asn, [])
            if ip in bhip:
                if ip in ports:
                    iplist.append(ip)
                iplist.append(bhip[ip])
            else:
                iplist.append(ip)
            ASNs[asn] = iplist
            ASDs[asn] = desc

        backcolorlist = colgen("60", "86", "ba", "ff")
        forecolorlist = colgen("a0", "70", "40", "20")

        s = "digraph trace {\n"

        s += "\n\tnode [shape=ellipse,color=black,style=solid];\n\n"

        s += "\n#ASN clustering\n"
        for asn in ASNs:
            s += '\tsubgraph cluster_%s {\n' % asn
            col = next(backcolorlist)
            s += '\t\tcolor="#%s%s%s";' % col
            s += '\t\tnode [fillcolor="#%s%s%s",style=filled];' % col
            s += '\t\tfontsize = 10;'
            s += '\t\tlabel = "%s\\n[%s]"\n' % (asn, ASDs[asn])
            for ip in ASNs[asn]:

                s += '\t\t"%s";\n' % ip
            s += "\t}\n"

        s += "#endpoints\n"
        for p in ports:
            s += '\t"%s" [shape=record,color=black,fillcolor=green,style=filled,label="%s|%s"];\n' % (p, p, "|".join(ports[p]))

        s += "\n#Blackholes\n"
        for bh in blackholes:
            s += '\t%s [shape=octagon,color=black,fillcolor=red,style=filled];\n' % bh

        if padding:
            s += "\n#Padding\n"
            pad = {}
            for _, rcv in self.res:
                if rcv.src not in ports and rcv.haslayer(conf.padding_layer):
                    p = rcv.getlayer(conf.padding_layer).load
                    if p != "\x00" * len(p):
                        pad[rcv.src] = None
            for rcv in pad:
                s += '\t"%s" [shape=triangle,color=black,fillcolor=red,style=filled];\n' % rcv

        s += "\n\tnode [shape=ellipse,color=black,style=solid];\n\n"

        for rtk in rt:
            s += "#---[%s\n" % repr(rtk)
            s += '\t\tedge [color="#%s%s%s"];\n' % next(forecolorlist)
            trace = rt[rtk]
            k = trace.keys()
            for n in range(min(k), max(k)):
                s += '\t%s ->\n' % trace[n]
            s += '\t%s;\n' % trace[max(k)]

        s += "}\n"
        self.graphdef = s

    def graph(self, ASres=None, padding=0, **kargs):
        """x.graph(ASres=conf.AS_resolver, other args):
        ASres=None          : no AS resolver => no clustering
        ASres=AS_resolver() : default whois AS resolver (riswhois.ripe.net)
        ASres=AS_resolver_cymru(): use whois.cymru.com whois database
        ASres=AS_resolver(server="whois.ra.net")
        format: output type (svg, ps, gif, jpg, etc.), passed to dot's "-T" option
        figsize: w,h tuple in inches. See matplotlib documentation
        target: filename. If None uses matplotlib to display
        prog: which graphviz program to use"""
        if ASres is None:
            ASres = conf.AS_resolver
        if (self.graphdef is None or
            self.graphASres != ASres or
                self.graphpadding != padding):
            self.make_graph(ASres, padding)

        return do_graph(self.graphdef, **kargs)


@conf.commands.register
def traceroute(target, dport=80, minttl=1, maxttl=30, sport=RandShort(), l4=None, filter=None, timeout=2, verbose=None, **kargs):
    """Instant TCP traceroute
traceroute(target, [maxttl=30,] [dport=80,] [sport=80,] [verbose=conf.verb]) -> None
"""
    if verbose is None:
        verbose = conf.verb
    if filter is None:
        # we only consider ICMP error packets and TCP packets with at
        # least the ACK flag set *and* either the SYN or the RST flag
        # set
        filter = "(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12)) or (tcp and (tcp[13] & 0x16 > 0x10))"
    if l4 is None:
        a, b = sr(IP(dst=target, id=RandShort(), ttl=(minttl, maxttl)) / TCP(seq=RandInt(), sport=sport, dport=dport),
                  timeout=timeout, filter=filter, verbose=verbose, **kargs)
    else:
        # this should always work
        filter = "ip"
        a, b = sr(IP(dst=target, id=RandShort(), ttl=(minttl, maxttl)) / l4,
                  timeout=timeout, filter=filter, verbose=verbose, **kargs)

    a = TracerouteResult(a.res)

    if verbose:
        a.show()
    return a, b


##########################
# Multi-Traceroute Class #
##########################
class MTR:
    #
    # Initialize Multi-Traceroute Object Vars...
    def __init__(self, nquery=1, target=''):
        self._nquery = nquery		# Number or traceroute queries
        self._ntraces = 1		# Number of trace runs
        self._iface = ''		# Interface to use for trace
        self._gw = ''			# Default Gateway IPv4 Address for trace
        self._netprotocol = 'TCP'  # MTR network protocol to use for trace
        self._target = target		# Session targets
        self._exptrg = []		# Expanded Session targets
        self._host2ip = {}		# Target Host Name to IP Address
        self._ip2host = {}		# Target IP Address to Host Name
        self._tcnt = 0			# Total Trace count
        self._tlblid = []		# Target Trace label IDs
        self._res = []			# Trace Send/Receive Response Packets
        self._ures = []			# Trace UnResponse Sent Packets
        self._ips = {}			# Trace Unique IPv4 Addresses
        self._hops = {}			# Traceroute Hop Ranges
        self._rt = []			# Individual Route Trace Summaries
        self._ports = {}		# Completed Targets & Ports
        self._portsdone = {}		# Completed Traceroutes & Ports
        self._rtt = {}			# Round Trip Times (msecs) for Trace Nodes
        self._unknownlabel = incremental_label('"Unk%i"')
        self._asres = conf.AS_resolver  # Initial ASN Resolver
        self._asns = {}			# Found AS Numbers for the MTR session
        self._asds = {}			# Associated AS Number descriptions
        self._unks = {}			# Unknown Hops ASN IP boundaries
        self._graphdef = None
        self._graphasres = 0
        self._graphpadding = 0

    #
    # Get the protocol name from protocol integer value.
    #
    #  proto - Protocol integer value.
    #
    #   Returns a string value representing the given integer protocol.
    def get_proto_name(self, proto):
        ps = str(proto)
        if ps == '6':
            pt = 'tcp'
        elif ps == '17':
            pt = 'udp'
        elif ps == '1':
            pt = 'icmp'
        else:
            pt = str(proto)
        return pt

    #
    # Compute Black Holes...
    def get_black_holes(self):
        for t in range(0, self._ntraces):
            for rtk in self._rt[t]:
                trace = self._rt[t][rtk]
                k = trace.keys()
                for n in range(min(k), max(k)):
                    if not n in trace:				# Fill in 'Unknown' hops
                        trace[n] = next(self._unknownlabel)
                if not rtk in self._portsdone:
                    if rtk[2] == 1:  # ICMP
                        bh = "%s %i/icmp" % (rtk[1], rtk[3])
                    elif rtk[2] == 6:  # TCP
                        bh = "{ip:s} {dp:d}/tcp".format(ip=rtk[1], dp=rtk[3])
                    elif rtk[2] == 17:  # UDP
                        bh = '%s %i/udp' % (rtk[1], rtk[3])
                    else:
                        bh = '%s %i/proto' % (rtk[1], rtk[2])
                    self._ips[rtk[1]] = None			# Add the Blackhole IP to list of unique IP Addresses
                    #
                    # Update trace with Blackhole info...
                    bh = '"{bh:s}"'.format(bh=bh)
                    trace[max(k) + 1] = bh
        #
        # Detection for Blackhole - Failed target not set as last Hop in trace...
        for t in range(0, self._ntraces):
            for rtk in self._rt[t]:
                trace = self._rt[t][rtk]
                k = trace.keys()
                if (' ' not in trace[max(k)]) and (':' not in trace[max(k)]):
                    if rtk[2] == 1:  # ICMP
                        bh = "%s %i/icmp" % (rtk[1], rtk[3])
                    elif rtk[2] == 6:  # TCP
                        bh = "{ip:s} {dp:d}/tcp".format(ip=rtk[1], dp=rtk[3])
                    elif rtk[2] == 17:  # UDP
                        bh = '%s %i/udp' % (rtk[1], rtk[3])
                    else:
                        bh = '%s %i/proto' % (rtk[1], rtk[2])
                    self._ips[rtk[1]] = None			# Add the Blackhole IP to list of unique IP Addresses
                    #
                    # Update trace with Blackhole info...
                    bh = '"{bh:s}"'.format(bh=bh)
                    trace[max(k) + 1] = bh

    #
    # Compute the Hop range for each trace...
    def compute_hop_ranges(self):
        n = 1
        for t in range(0, self._ntraces):
            for rtk in self._rt[t]:
                trace = self._rt[t][rtk]
                k = trace.keys()
                #
                # Detect Blackhole Endpoints...
                h = rtk[1]
                mt = max(k)
                if not ':' in trace[max(k)]:
                    h = trace[max(k)].replace('"', '')  # Add a Blackhole Endpoint (':' Char does not exist)
                    if max(k) == 1:
                        #
                        # Special case: Max TTL set to 1...
                        mt = 1
                    else:
                        mt = max(k) - 1			# Blackhole - remove Hop for Blackhole -> Host never reached
                hoplist = self._hops.get(h, [])     	# Get previous hop value
                hoplist.append([n, min(k), mt])		# Append trace hop range for this trace
                self._hops[h] = hoplist			# Update mtr Hop value
                n += 1

    #
    # Get AS Numbers...
    def get_asns(self, privaddr=0):
        """Obtain associated AS Numbers for IPv4 Addreses.
           privaddr: 0 - Normal display of AS numbers,
                     1 - Do not show an associated AS Number bound box (cluster) on graph for a private IPv4 Address."""
        ips = {}
        if privaddr:
            for k, v in self._ips.items():
                if not is_private_addr(k):
                    ips[k] = v
        else:
            ips = self._ips
        #
        # Special case for the loopback IP Address: 127.0.0.1 - Do not ASN resolve...
        if '127.0.0.1' in ips:
            del ips['127.0.0.1']
        #
        # ASN Lookup...
        asnquerylist = dict.fromkeys(map(lambda x: x.rsplit(" ", 1)[0], ips)).keys()
        if self._asres is None:
            asnlist = []
        else:
            try:
                asnlist = self._asres.resolve(*asnquerylist)
            except:
                pass
        for ip, asn, desc, in asnlist:
            if asn is None:
                continue
            iplist = self._asns.get(asn, [])  # Get previous ASN value
            iplist.append(ip)			# Append IP Address to previous ASN

            #
            # If ASN is a string Convert to a number: (i.e., 'AS3257' => 3257)
            if type(asn) == str:
                asn = asn.upper()
                asn = asn.replace('AS', '')
                try:
                    asn = int(asn)
                    self._asns[asn] = iplist
                    self._asds[asn] = desc
                except:
                    continue
            else:
                self._asns[asn] = iplist
                self._asds[asn] = desc

    #
    #  Get the ASN for a given IP Address.
    #
    #    ip - IP Address to get the ASN for.
    #
    #   Return the ASN for a given IP Address if found.
    #   A -1 is returned if not found.
    def get_asn_ip(self, ip):
        for a in self._asns:
            for i in self._asns[a]:
                if ip == i:
                    return a
        return -1

    #
    # Guess Traceroute 'Unknown (Unkn) Hops' ASNs.
    #
    #   Technique: Method to guess ASNs for Traceroute 'Unknown Hops'.
    #              If the assign ASN for the known Ancestor IP is the
    #              same as the known Descendant IP then use this ASN
    #              for the 'Unknown Hop'.
    #              Special case guess: If the Descendant IP is a
    #              Endpoint Host Target the assign it to its
    #              associated ASN.
    def guess_unk_asns(self):
        t = 1
        for q in range(0, self._ntraces):
            for rtk in self._rt[q]:
                trace = self._rt[q][rtk]
                tk = trace.keys()
                begip = endip = ''
                unklist = []
                for n in range(min(tk), (max(tk) + 1)):
                    if trace[n].find('Unk') == -1:
                        #
                        # IP Address Hop found...
                        if len(unklist) == 0:
                            #
                            # No 'Unknown Hop' found yet...
                            begip = trace[n]
                        else:
                            #
                            # At least one Unknown Hop found - Store IP boundary...
                            endip = trace[n]
                            for u in unklist:
                                idx = begip.find(':')
                                if idx != -1:		# Remove Endpoint Trace port info: '"162.144.22.85":T443'
                                    begip = begip[:idx]
                                idx = endip.find(':')
                                if idx != -1:
                                    endip = endip[:idx]
                                #
                                # u[0] - Unknown Hop name...
                                # u[1] - Hop number...
                                self._unks[u[0]] = [begip, endip, '{t:d}:{h:d}'.format(t=t, h=u[1])]
                            #
                            # Init var for new Unknown Hop search...
                            begip = endip = ''
                            unklist = []
                    else:
                        #
                        # 'Unknown Hop' found...
                        unklist.append([trace[n], n])
                t += 1					# Inc next trace count
        #
        # Assign 'Unknown Hop' ASN...
        for u in self._unks:
            bip = self._unks[u][0]
            bip = bip.replace('"', '')			# Begin IP - Strip off surrounding double quotes (")
            basn = self.get_asn_ip(bip)
            if basn == -1:
                continue
            eip = self._unks[u][1]
            eip = eip.replace('"', '')
            easn = self.get_asn_ip(eip)
            if easn == -1:
                continue
            #
            # Append the 'Unknown Hop' to an ASN if
            # Ancestor/Descendant IP ASN match...
            if basn == easn:
                self._asns[basn].append(u.replace('"', ''))
            else:
                #
                # Special case guess: If the Descendant IP is
                # a Endpoint Host Target the assign it to its
                # associated ASN.
                for d in self._tlblid:
                    if eip in d:
                        self._asns[easn].append(u.replace('"', ''))
                        break

    # Make the DOT graph...
    def make_dot_graph(self, ASres=None, padding=0, vspread=0.75, title="Multi-Traceroute (MTR) Probe", timestamp="", rtt=1):
        import datetime
        if ASres is None:
            self._asres = conf.AS_resolver
        self._graphasres = ASres
        self._graphpadding = padding
        #
        # ASN box color generator...
        backcolorlist = colgen("60", "86", "ba", "ff")
        #
        # Edge (trace arrows)  color generator...
        forecolorlist = colgen("a0", "70", "40", "20")
        #
        # Begin the DOT Digraph...
        s = "### kamene Multi-Traceroute (MTR) DOT Graph Results ({t:s}) ###\n".format(t=datetime.datetime.now().isoformat(' '))

        s += "\ndigraph mtr {\n"
        #
        # Define the default graph attributes...
        s += '\tgraph [bgcolor=transparent,ranksep={vs:.2f}];\n'.format(vs=vspread)
        #
        # Define the default node shape and drawing color...
        s += '\tnode [shape="ellipse",fontname="Sans-Serif",fontsize=11,color="black",gradientangle=270,fillcolor="white:#a0a0a0",style="filled"];\n'

        #
        # Combine Trace Probe Begin Points...
        #
        #                   k0       k1   k2       v0   v1           k0         k1    k2       v0   v1
        # Ex: bp = {('192.168.43.48',5555,''): ['T1','T3'], ('192.168.43.48',443,'https'): ['T2','T4']}
        bp = {}				# ep -> A single services label for a given IP
        for d in self._tlblid:  # k            v0          v1               v2       v3   v4    v5      v6   v7
            for k, v in d.items():  # Ex: k:  '162.144.22.87' v: ('T1', '192.168.43.48', '162.144.22.87', 6, 443, 'https', 'SA', '')
                p = bp.get((v[1], v[4], v[5]))
                if p == None:
                    bp[(v[1], v[4], v[5])] = [v[0]]  # Add new (TCP Flags / ICMP / Proto) and initial trace ID
                else:
                    bp[(v[1], v[4], v[5])].append(v[0])  # Append additional trace IDs
        #
        # Combine Begin Point services...
        #                   k                 sv0           sv1            sv0          sv1
        # Ex bpip = {'192.168.43.48': [('<BT2>T2|<BT4>T4', 'https(443)'), ('<BB1>T1|<BT3>T3', '5555')]}
        bpip = {}			# epip -> Combined Endpoint services label for a given IP
        for k, v in bp.items():
            tr = ''
            for t in range(0, len(v)):
                if tr == '':
                    tr += '<B{ts:s}>{ts:s}'.format(ts=v[t])
                else:
                    tr += '|<B{ts:s}>{ts:s}'.format(ts=v[t])
            p = k[2]
            if p == '':			# Use port number not name if resolved
                p = str(k[1])
            else:
                p += '(' + str(k[1]) + ')'  # Use both name and port
            if k[0] in bpip:
                bpip[k[0]].append((tr, p))
            else:
                bpip[k[0]] = [(tr, p)]

        #
        # Create Endpoint Target Clusters...
        epc = {}			# Endpoint Target Cluster Dictionary
        epip = []			# Endpoint IPs array
        oip = []			# Only Endpoint IP array
        epprb = []			# Endpoint Target and Probe the same IP array
        for d in self._tlblid:		# Spin thru Target IDs
            for k, v in d.items():  # Get access to Target Endpoints
                h = k
                if v[6] == 'BH':  # Add a Blackhole Endpoint Target
                    h = '{bh:s} {bhp:d}/{bht:s}'.format(bh=k, bhp=v[4], bht=v[3])
                elif v[1] == v[2]:  # When the Target and host running the mtr session are
                    epprb.append(k)  # the same then append IP to list target and probe the same array
                epip.append(h)
                oip.append(k)
        #
        # Create unique arrays...
        uepip = set(epip)		# Get a unique set of Endpoint IPs
        uepipo = set(oip)		# Get a unique set of Only Endpoint IPs
        uepprb = set(epprb)		# Get a unique set of Only IPs: Endpoint Target and Probe the same
        #
        # Now create unique endpoint target clusters....
        for ep in uepip:
            #
            # Get Host only string...
            eph = ep
            f = ep.find(' ')
            if f >= 0:
                eph = ep[0:f]
            #
            # Build Traceroute Hop Range label...
            if ep in self._hops:  # Is Endpoint IP in the Hops dictionary
                hr = self._hops[ep]
            elif eph in self._hops:  # Is Host only endpoint in the Hops dictionary
                hr = self._hops[eph]
            else:
                continue		# Not found in the Hops dictionary

            l = len(hr)
            if l == 1:
                hrs = "Hop Range ("
            else:
                hrs = "Hop Ranges ("
            c = 0
            for r in hr:
                hrs += 'T{s1:d}: {s2:d} &rarr; {s3:d}'.format(s1=r[0], s2=r[1], s3=r[2])
                c += 1
                if c < l:
                    hrs += ', '
            hrs += ')'
            ecs = "\t\t### MTR Target Cluster ###\n"
            uep = ep.replace('.', '_')
            uep = uep.replace(' ', '_')
            uep = uep.replace('/', '_')
            gwl = ''
            if self._gw == eph:
                gwl = ' (Default Gateway)'
            ecs += '\t\tsubgraph cluster_{ep:s} {{\n'.format(ep=uep)
            ecs += '\t\t\ttooltip="MTR Target: {trg:s}{gwl:s}";\n'.format(trg=self._ip2host[eph], gwl=gwl)
            ecs += '\t\t\tcolor="darkgreen";\n'
            ecs += '\t\t\tfontsize=11;\n'
            ecs += '\t\t\tfontname="Sans-Serif";\n'
            ecs += '\t\t\tgradientangle=270;\n'
            ecs += '\t\t\tfillcolor="white:#a0a0a0";\n'
            ecs += '\t\t\tstyle="filled,rounded";\n'
            ecs += '\t\t\tpenwidth=2;\n'
            ecs += '\t\t\tlabel=<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0"><TR><TD ALIGN="center"><B>Target: {h:s}{gwl:s}</B></TD></TR><TR><TD><FONT POINT-SIZE="9">{hr:s}</FONT></TD></TR></TABLE>>;\n'.format(h=self._ip2host[eph], gwl=gwl, hr=hrs)
            ecs += '\t\t\tlabelloc="b";\n'
            pre = ''
            if ep in uepprb:		# Special Case: Separate Endpoint Target from Probe
                pre = '_'			# when they are the same -> Prepend an underscore char: '_'
            ecs += '\t\t\t"{pre:s}{ep:s}";\n'.format(pre=pre, ep=ep)
            ecs += "\t\t}\n"
            #
            # Store Endpoint Cluster...
            epc[ep] = ecs

        #
        # Create ASN Clusters (i.e. DOT subgraph and nodes)
        s += "\n\t### ASN Clusters ###\n"
        cipall = []			# Array of IPs consumed by all ASN Cluster
        cepipall = []			# Array of IP Endpoints (Targets) consumed by all ASN Cluster
        for asn in self._asns:
            cipcur = []
            s += '\tsubgraph cluster_{asn:d} {{\n'.format(asn=asn)
            s += '\t\ttooltip="AS: {asn:d} - [{asnd:s}]";\n'.format(asn=asn, asnd=self._asds[asn])
            col = next(backcolorlist)
            s += '\t\tcolor="#{s0:s}{s1:s}{s2:s}";\n'.format(s0=col[0], s1=col[1], s2=col[2])
            #
            # Fill in ASN Cluster the associated generated color using an 11.7% alpha channel value (30/256)...
            s += '\t\tfillcolor="#{s0:s}{s1:s}{s2:s}30";\n'.format(s0=col[0], s1=col[1], s2=col[2])
            s += '\t\tstyle="filled,rounded";\n'
            s += '\t\tnode [color="#{s0:s}{s1:s}{s2:s}",gradientangle=270,fillcolor="white:#{s0:s}{s1:s}{s2:s}",style="filled"];\n'.format(s0=col[0], s1=col[1], s2=col[2])
            s += '\t\tfontsize=10;\n'
            s += '\t\tfontname="Sans-Serif";\n'
            s += '\t\tlabel=<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0"><TR><TD ALIGN="center"><B><FONT POINT-SIZE="11">AS: {asn:d}</FONT></B></TD></TR><TR><TD>[{des:s}]</TD></TR></TABLE>>;\n'.format(asn=asn, des=self._asds[asn])
            s += '\t\tlabelloc="t";\n'
            s += '\t\tpenwidth=3;\n'
            for ip in self._asns[asn]:
                #
                # Only add IP if not an Endpoint Target...
                if not ip in uepipo:
                    #
                    # Spin thru all traces and only Add IP if not an ICMP Destination Unreachable node...
                    for tr in range(0, self._ntraces):
                        for rtk in self._rt[tr]:
                            trace = self._rt[tr][rtk]
                            k = trace.keys()
                            for n in range(min(k), (max(k) + 1)):
                                #
                                # Check for not already added...
                                if not ip in cipall:
                                    #
                                    # Add IP Hop - found in trace and not an ICMP Destination Unreachable node...
                                    if '"{ip:s}"'.format(ip=ip) == trace[n]:
                                        s += '\t\t"{ip:s}" [tooltip="Hop Host: {ip:s}"];\n'.format(ip=ip)
                                        cipall.append(ip)
                    #
                    # Special check for ICMP Destination Unreachable nodes...
                    if ip in self._ports:
                        for p in self._ports[ip]:
                            if p.find('ICMP dest-unreach') >= 0:
                                #
                                # Check for not already added...
                                uip = '{uip:s} 3/icmp'.format(uip=ip)
                                if uip not in cipall:
                                    s += '\t\t"{uip:s}";\n'.format(uip=uip)
                                    cipall.append(uip)
                else:
                    cipcur.append(ip)  # Current list of Endpoints consumed by this ASN Cluster
                    cepipall.append(ip)  # Accumulated list of Endpoints consumed by all ASN Clusters
            #
            # Add Endpoint Cluster(s) if part of this ASN Cluster (Nested Clusters)...
            if len(cipcur) > 0:
                for ip in cipcur:
                    for e in epc:  # Loop thru each Endpoint Target Clusters
                        h = e
                        f = e.find(' ')  # Strip off 'port/proto'
                        if f >= 0:
                            h = e[0:f]
                        if h == ip:
                            s += epc[e]
            s += "\t}\n"
        #
        # Add any Endpoint Target Clusters not consumed by an ASN Cluster (Stand-alone Cluster)
        # and not the same as the host running the mtr session...
        for ip in epc:
            h = ip
            f = h.find(' ')			# Strip off 'port/proto'
            if f >= 0:
                h = ip[0:f]
            if not h in cepipall:
                for k, v in bpip.items():  # Check for target = host running the mtr session - Try to Add
                    if k != h:		# this Endpoint target to the Probe Target Cluster below.
                        s += epc[ip]		# Finally add the Endpoint Cluster if Stand-alone and
                        # not running the mtr session.

        #
        # Probe Target Cluster...
        s += "\n\t### Probe Target Cluster ###\n"
        s += '\tsubgraph cluster_probe_Title {\n'
        p = ''
        for k, v in bpip.items():
            p += ' {ip:s}'.format(ip=k)
        s += '\t\ttooltip="Multi-Traceroute (MTR) Probe: {ip:s}";\n'.format(ip=p)
        s += '\t\tcolor="darkorange";\n'
        s += '\t\tgradientangle=270;\n'
        s += '\t\tfillcolor="white:#a0a0a0";\n'
        s += '\t\tstyle="filled,rounded";\n'
        s += '\t\tpenwidth=3;\n'
        s += '\t\tfontsize=11;\n'
        s += '\t\tfontname="Sans-Serif";\n'
        #
        # Format Label including trace targets...
        tstr = ''
        for t in self._target:
            tstr += '<TR><TD ALIGN="center"><FONT POINT-SIZE="9">Target: {t:s} ('.format(t=t)
            #
            # Append resolve IP Addresses...
            l = len(self._host2ip[t])
            c = 0
            for ip in self._host2ip[t]:
                tstr += '{ip:s} &rarr; '.format(ip=ip)
                #
                # Append all associated Target IDs...
                ti = []
                for d in self._tlblid:		# Spin thru Target IDs
                    for k, v in d.items():  # Get access to Target ID (v[0])
                        if k == ip:
                            ti.append(v[0])
                lt = len(ti)
                ct = 0
                for i in ti:
                    tstr += '{i:s}'.format(i=i)
                    ct += 1
                    if ct < lt:
                        tstr += ', '
                c += 1
                if c < l:
                    tstr += ', '
            tstr += ')</FONT></TD></TR>'
        s += '\t\tlabel=<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0"><TR><TD ALIGN="center"><B>{s0:s}</B></TD></TR>'.format(s0=title)
        if timestamp != "":
            s += '<TR><TD ALIGN="center"><FONT POINT-SIZE="9">{s0:s}</FONT></TD></TR>'.format(s0=timestamp)
        s += '{s0:s}</TABLE>>;\n'.format(s0=tstr)
        s += '\t\tlabelloc="t";\n'
        for k, v in bpip.items():
            s += '\t\t"{ip:s}";\n'.format(ip=k)
        #
        # Add in any Endpoint target that is the same as the host running the mtr session...
        for ip in epc:
            h = ip
            f = h.find(' ')		# Strip off 'port/proto'
            if f >= 0:
                h = ip[0:f]
            for k, v in bpip.items():  # Check for target = host running the mtr session - Try to Add
                if k == h:		# this Endpoint target to the Probe Target Cluster.
                    s += epc[ip]
        s += "\t}\n"

        #
        # Default Gateway Cluster...
        s += "\n\t### Default Gateway Cluster ###\n"
        if self._gw != '':
            if self._gw in self._ips:
                if not self._gw in self._exptrg:
                    s += '\tsubgraph cluster_default_gateway {\n'
                    s += '\t\ttooltip="Default Gateway Host: {gw:s}";\n'.format(gw=self._gw)
                    s += '\t\tcolor="goldenrod";\n'
                    s += '\t\tgradientangle=270;\n'
                    s += '\t\tfillcolor="white:#b8860b30";\n'
                    s += '\t\tstyle="filled,rounded";\n'
                    s += '\t\tpenwidth=3;\n'
                    s += '\t\tfontsize=11;\n'
                    s += '\t\tfontname="Sans-Serif";\n'
                    s += '\t\tlabel=<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" ALIGN="center"><TR><TD><B><FONT POINT-SIZE="9">Default Gateway</FONT></B></TD></TR></TABLE>>;\n'
                    s += '\t\t"{gw:s}" [shape="diamond",fontname="Sans-Serif",fontsize=11,color="black",gradientangle=270,fillcolor="white:goldenrod",style="rounded,filled",tooltip="Default Gateway Host: {gw:s}"];\n'.format(gw=self._gw)
                    s += "\t}\n"

        #
        # Build Begin Point strings...
        # Ex bps = '192.168.43.48" [shape="record",color="black",gradientangle=270,fillcolor="white:darkorange",style="filled",'
        #        + 'label="192.168.43.48\nProbe|{http|{<BT1>T1|<BT3>T3}}|{https:{<BT2>T4|<BT3>T4}}"];'
        s += "\n\t### Probe Begin Traces ###\n"
        for k, v in bpip.items():
            tr = ''
            for sv in v:
                if self._netprotocol == 'ICMP':
                    if sv[1].find('ICMP') >= 0:
                        ps = '{p:s} echo-request'.format(p=sv[1])
                    else:
                        ps = 'ICMP({p:s}) echo-request'.format(p=sv[1])
                else:
                    ps = '{pr:s}: {p:s}'.format(pr=self._netprotocol, p=sv[1])
                if tr == '':
                    tr += '{{{ps:s}|{{{t:s}}}}}'.format(ps=ps, t=sv[0])
                else:
                    tr += '|{{{ps:s}|{{{t:s}}}}}'.format(ps=ps, t=sv[0])
            bps1 = '\t"{ip:s}" [shape="record",color="black",gradientangle=270,fillcolor="white:darkorange",style="filled,rounded",'.format(ip=k)
            if self._iface != '':
                bps2 = 'label="Probe: {ip:s}\\nNetwork Interface: {ifc:s}|{tr:s}",tooltip="Begin Host Probe: {ip:s}"];\n'.format(ip=k, ifc=self._iface, tr=tr)
            else:
                bps2 = 'label="Probe: {ip:s}|{tr:s}",tooltip="Begin Host Probe: {ip:s}"];\n'.format(ip=k, tr=tr)
            s += bps1 + bps2

        #
        s += "\n\t### Target Endpoints ###\n"
        #
        # Combine Trace Target Endpoints...
        #
        #                   k0       k1   k2       v0   v1   v2           k0     k1     k2       v0   v1   v2
        # Ex: ep = {('162.144.22.87',80,'http'): ['SA','T1','T3'], ('10.14.22.8',443,'https'): ['SA','T2','T4']}
        ep = {}				# ep -> A single services label for a given IP
        for d in self._tlblid:  # k            v0          v1               v2       v3   v4    v5      v6  v7
            for k, v in d.items():  # Ex: k:  162.144.22.87 v: ('T1', '10.222.222.10', '162.144.22.87', 6, 443, 'https', 'SA', '')
                if not v[6] == 'BH':  # Blackhole detection - do not create Endpoint
                    p = ep.get((k, v[4], v[5]))
                    if p == None:
                        ep[(k, v[4], v[5])] = [v[6], v[0]]  # Add new (TCP Flags / ICMP type / Proto) and initial trace ID
                    else:
                        ep[(k, v[4], v[5])].append(v[0])  # Append additional trace IDs
        #
        # Combine Endpoint services...
        #                   k                                 v                                 v
        #                   k                 sv0            sv1     sv2          sv0          sv1    sv2
        # Ex epip = {'206.111.13.58': [('<ET8>T8|<ET10>T10', 'https', 'SA'), ('<ET7>T7|<ET6>T6', 'http', 'SA')]}
        epip = {}			# epip -> Combined Endpoint services label for a given IP
        for k, v in ep.items():
            tr = ''
            for t in range(1, len(v)):
                if tr == '':
                    tr += '<E{ts:s}>{ts:s}'.format(ts=v[t])
                else:
                    tr += '|<E{ts:s}>{ts:s}'.format(ts=v[t])
            p = k[2]
            if p == '':			# Use port number not name if resolved
                p = str(k[1])
            else:
                p += '(' + str(k[1]) + ')'  # Use both name and port
            if k[0] in epip:
                epip[k[0]].append((tr, p, v[0]))
            else:
                epip[k[0]] = [(tr, p, v[0])]
        #
        # Build Endpoint strings...
        # Ex eps = '162.144.22.87" [shape=record,color="black",gradientangle=270,fillcolor="darkgreen:green",style=i"filled,rounded",'
        #        + 'label="162.144.22.87\nTarget|{{<ET1>T1|<ET3>T3}|https SA}|{{<ET2>T4|<ET3>T4}|http SA}"];'
        for k, v in epip.items():
            tr = ''
            for sv in v:
                if self._netprotocol == 'ICMP':
                    ps = 'ICMP(0) echo-reply'
                else:
                    ps = '{p:s} {f:s}'.format(p=sv[1], f=sv[2])
                if tr == '':
                    tr += '{{{{{t:s}}}|{ps:s}}}'.format(t=sv[0], ps=ps)
                else:
                    tr += '|{{{{{t:s}}}|{ps:s}}}'.format(t=sv[0], ps=ps)
            pre = ''
            if k in uepprb:		# Special Case: Separate Endpoint Target from Probe
                pre = '_'			# when they are the same
            eps1 = '\t"{pre:s}{ip:s}" [shape="record",color="black",gradientangle=270,fillcolor="darkgreen:green",style="filled,rounded",'.format(pre=pre, ip=k)
            eps2 = 'label="Resolved Target\\n{ip:s}|{tr:s}",tooltip="MTR Resolved Target: {ip:s}"];\n'.format(ip=k, tr=tr)
            s += eps1 + eps2

        #
        # Blackholes...
        #
        # ***Note: Order matters: If a hop is both a Blackhole on one trace and
        #                         a ICMP destination unreachable hop on another,
        #                         it will appear in the dot file as two nodes in
        #                         both sections. The ICMP destination unreachable
        #                         hop node will take precedents and appear only
        #                         since it is defined last.
        s += "\n\t### Blackholes ###\n"
        bhhops = []
        for d in self._tlblid:  # k             v0         v1               v2           v3    v4   v5   v6    v7
            for k, v in d.items():  # Ex: k:  162.144.22.87 v: ('T1', '10.222.222.10', '162.144.22.87', 'tcp', 5555, '', 'BH', 'I3')
                if v[6] == 'BH':  # Blackhole detection
                    #
                    # If both a target blackhole and an ICMP packet hop, then skip creating this
                    # node we be created in the 'ICMP Destination Unreachable Hops' section.
                    if v[7] != 'I3':  # ICMP destination not reached detection
                        nd = '{b:s} {prt:d}/{pro:s}'.format(b=v[2], prt=v[4], pro=v[3])
                        if self._netprotocol == 'ICMP':
                            bhh = '{b:s}<BR/><FONT POINT-SIZE="9">ICMP(0) echo-reply</FONT>'.format(b=v[2])
                        else:
                            bhh = nd
                        #
                        # If not already added...
                        if bhh not in bhhops:
                            lb = 'label=<{lh:s}<BR/><FONT POINT-SIZE="8">Failed Target</FONT>>'.format(lh=bhh)
                            s += '\t"{bh:s}" [{l:s},shape="doubleoctagon",color="black",gradientangle=270,fillcolor="white:red",style="filled,rounded",tooltip="Failed MTR Resolved Target: {b:s}"];\n'.format(bh=nd, l=lb, b=v[2])
                            bhhops.append(bhh)

        #
        # ICMP Destination Unreachable Hops...
        s += "\n\t### ICMP Destination Unreachable Hops ###\n"
        for d in self._ports:
            for p in self._ports[d]:
                if d in self._exptrg:
                    #
                    # Create Node: Target same as node that returns an ICMP packet...
                    if p.find('ICMP dest-unreach') >= 0:
                        unreach = 'ICMP(3): Destination'
                        #                   0    1        2             3          4  5
                        # Ex ICMP ports: '<I3> ICMP dest-unreach port-unreachable 17 53'
                        icmpparts = p.split(' ')
                        if icmpparts[3] == 'network-unreachable':
                            unreach += '/Network'
                        elif icmpparts[3] == 'host-unreachable':
                            unreach += '/Host'
                        elif icmpparts[3] == 'protocol-unreachable':
                            unreach += '/Protocol'
                        elif icmpparts[3] == 'port-unreachable':
                            unreach += '/Port'
                        protoname = self.get_proto_name(icmpparts[4])
                        protoport = '{pr:s}/{pt:s}'.format(pr=icmpparts[5], pt=protoname)
                        lb = 'label=<{lh:s} {pp:s}<BR/><FONT POINT-SIZE="8">{u:s} Unreachable</FONT><BR/><FONT POINT-SIZE="8">Failed Target</FONT>>'.format(lh=d, pp=protoport, u=unreach)
                        s += '\t"{lh:s} {pp:s}" [{lb:s},shape="doubleoctagon",color="black",gradientangle=270,fillcolor="yellow:red",style="filled,rounded",tooltip="{u:s} Unreachable, Failed Resolved Target: {lh:s} {pp:s}"];\n'.format(lb=lb, pp=protoport, lh=d, u=unreach)
                else:
                    #
                    # Create Node: Target not same as node that returns an ICMP packet...
                    if p.find('ICMP dest-unreach') >= 0:
                        unreach = 'ICMP(3): Destination'
                        if p.find('network-unreachable') >= 0:
                            unreach += '/Network'
                        elif p.find('host-unreachable') >= 0:
                            unreach += '/Host'
                        elif p.find('protocol-unreachable') >= 0:
                            unreach += '/Protocol'
                        elif p.find('port-unreachable') >= 0:
                            unreach += '/Port'
                        lb = 'label=<{lh:s} 3/icmp<BR/><FONT POINT-SIZE="8">{u:s} Unreachable</FONT>>'.format(lh=d, u=unreach)
                        s += '\t"{lh:s} 3/icmp" [{lb:s},shape="doubleoctagon",color="black",gradientangle=270,fillcolor="white:yellow",style="filled,rounded",tooltip="{u:s} Unreachable, Hop Host: {lh:s}"];\n'.format(lb=lb, lh=d, u=unreach)
        #
        # Padding check...
        if self._graphpadding:
            s += "\n\t### Nodes With Padding ###\n"
            pad = {}
            for t in range(0, self._ntraces):
                for _, rcv in self._res[t]:
                    if rcv.src not in self._ports and rcv.haslayer(conf.padding_layer):
                        p = rcv.getlayer(conf.padding_layer).load
                        if p != "\x00" * len(p):
                            pad[rcv.src] = None
            for sr in pad:
                lb = 'label=<<BR/>{r:s}<BR/><FONT POINT-SIZE="8">Padding</FONT>>'.format(r=sr)
                s += '\t"{r:s}" [{l:s},shape="box3d",color="black",gradientangle=270,fillcolor="white:red",style="filled,rounded"];\n'.format(r=sr, l=lb)

        #
        # Draw each trace (i.e., DOT edge) for each number of queries...
        s += "\n\t### Traces ###\n"
        t = 0
        for q in range(0, self._ntraces):
            for rtk in self._rt[q]:
                s += "\t### T{tr:d} -> {r:s} ###\n".format(tr=(t + 1), r=repr(rtk))
                col = next(forecolorlist)
                s += '\tedge [color="#{s0:s}{s1:s}{s2:s}"];\n'.format(s0=col[0], s1=col[1], s2=col[2])
                #
                # Probe Begin Point (i.e., Begining of a trace)...
                for k, v in self._tlblid[t].items():
                    ptr = probe = v[1]
                    s += '\t"{bp:s}":B{tr:s}:s -> '.format(bp=ptr, tr=v[0])
                #
                # In between traces (i.e., Not at the begining or end of a trace)...
                trace = self._rt[q][rtk]
                tk = trace.keys()
                ntr = trace[min(tk)]
                #
                # Skip in between traces if there are none...
                if len(trace) > 1:
                    lb = 'Trace: {tr:d}:{tn:d}, {lbp:s} -> {lbn:s}'.format(tr=(t + 1), tn=min(tk), lbp=ptr, lbn=ntr.replace('"', ''))
                    if not 'Unk' in ntr:
                        lb += ' (RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms))'.format(prb=probe, lbn=ntr.replace('"', ''), rtt=self._rtt[t + 1][min(tk)])
                    if rtt:
                        if not 'Unk' in ntr:
                            llb = 'Trace: {tr:d}:{tn:d}, RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms)'.format(tr=(t + 1), tn=min(tk), prb=probe, lbn=ntr.replace('"', ''), rtt=self._rtt[t + 1][min(tk)])
                            s += '{ntr:s} [label=<<FONT POINT-SIZE="8">&nbsp; {rtt:s}ms</FONT>>,edgetooltip="{lb:s}",labeltooltip="{llb:s}"];\n'.format(ntr=ntr, rtt=self._rtt[t + 1][min(tk)], lb=lb, llb=llb)
                        else:
                            s += '{ntr:s} [edgetooltip="{lb:s}"];\n'.format(ntr=ntr, lb=lb)
                    else:
                        s += '{ntr:s} [edgetooltip="{lb:s}"];\n'.format(ntr=ntr, lb=lb)
                    for n in range(min(tk) + 1, max(tk)):
                        ptr = ntr
                        ntr = trace[n]
                        lb = 'Trace: {tr:d}:{tn:d}, {lbp:s} -> {lbn:s}'.format(tr=(t + 1), tn=n, lbp=ptr.replace('"', ''), lbn=ntr.replace('"', ''))
                        if not 'Unk' in ntr:
                            lb += ' (RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms))'.format(prb=probe, lbn=ntr.replace('"', ''), rtt=self._rtt[t + 1][n])
                        if rtt:
                            if not 'Unk' in ntr:
                                llb = 'Trace: {tr:d}:{tn:d}, RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms)'.format(tr=(t + 1), tn=n, prb=probe, lbn=ntr.replace('"', ''), rtt=self._rtt[t + 1][n])
                                #
                                # Special check to see if the next and previous nodes are the same.
                                # If yes use the DOT 'xlabel' attribute to spread out labels so that they
                                # do not clash and 'forcelabel' so that they are placed.
                                if ptr == ntr:
                                    s += '\t{ptr:s} -> {ntr:s} [xlabel=<<FONT POINT-SIZE="8">&nbsp; {rtt:s}ms</FONT>>,forcelabel=True,edgetooltip="{lb:s}",labeltooltip="{llb:s}"];\n'.format(ptr=ptr, ntr=ntr, rtt=self._rtt[t + 1][n], lb=lb, llb=llb)
                                else:
                                    s += '\t{ptr:s} -> {ntr:s} [label=<<FONT POINT-SIZE="8">&nbsp; {rtt:s}ms</FONT>>,edgetooltip="{lb:s}",labeltooltip="{llb:s}"];\n'.format(ptr=ptr, ntr=ntr, rtt=self._rtt[t + 1][n], lb=lb, llb=llb)
                            else:
                                s += '\t{ptr:s} -> {ntr:s} [edgetooltip="{lb:s}"];\n'.format(ptr=ptr, ntr=ntr, lb=lb)
                        else:
                            s += '\t{ptr:s} -> {ntr:s} [edgetooltip="{lb:s}"];\n'.format(ptr=ptr, ntr=ntr, lb=lb)
                #
                # Enhance target Endpoint (i.e., End of a trace) replacement...
                for k, v in self._tlblid[t].items():
                    if v[6] == 'BH':		# Blackhole detection - do not create Enhanced Endpoint
                        #
                        # Check for Last Hop / Backhole (Failed Target) match:
                        lh = trace[max(tk)]
                        lhicmp = False
                        if lh.find(':I3') >= 0:  # Is last hop and ICMP packet from target?
                            lhicmp = True
                        f = lh.find(' ')		# Strip off 'port/proto' ''"100.41.207.244":I3'
                        if f >= 0:
                            lh = lh[0:f]
                        f = lh.find(':')		# Strip off 'proto:port' -> '"100.41.207.244 801/tcp"'
                        if f >= 0:
                            lh = lh[0:f]
                        lh = lh.replace('"', '')  # Remove surrounding double quotes ("")
                        if k == lh:			# Does Hop match final Target?
                            #
                            # Backhole last hop matched target:
                            #
                            # Check to skip in between traces...
                            if len(trace) > 1:
                                s += '\t{ptr:s} -> '.format(ptr=ntr)
                            if lhicmp:
                                #
                                # Last hop is an ICMP packet from target and was reached...
                                lb = 'Trace: {tr:d}:{tn:d}, {lbp:s} -> {lbn:s}'.format(tr=(t + 1), tn=max(tk), lbp=ntr.replace('"', ''), lbn=k)
                                lb += ' (RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms))'.format(prb=v[1], lbn=lh, rtt=self._rtt[t + 1][max(tk)])
                                if rtt:
                                    llb = 'Trace: {tr:d}:{tn:d}, RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms)'.format(tr=(t + 1), tn=max(tk), prb=v[1], lbn=k, rtt=self._rtt[t + 1][max(tk)])
                                    s += '"{bh:s} {bhp:d}/{bht:s}" [style="solid",label=<<FONT POINT-SIZE="8">&nbsp; {rtt:s}ms</FONT>>,edgetooltip="{lb:s}",labeltooltip="{llb:s}"];\n'.format(bh=k, bhp=v[4], bht=v[3], rtt=self._rtt[t + 1][max(tk)], lb=lb, llb=llb)
                                else:
                                    s += '"{bh:s} {bhp:d}/{bht:s}" [style="solid",edgetooltip="{lb:s}"];\n'.format(bh=k, bhp=v[4], bht=v[3], lb=lb)
                            else:
                                #
                                # Last hop is not ICMP packet from target (Fake hop - never reached - use dashed trace)...
                                lb = 'Trace: {tr:d} - Failed MTR Resolved Target: {bh:s} {bhp:d}/{bht:s}'.format(tr=(t + 1), bh=k, bhp=v[4], bht=v[3])
                                s += '"{bh:s} {bhp:d}/{bht:s}" [style="dashed",label=<<FONT POINT-SIZE="8">&nbsp; T{tr:d}</FONT>>,edgetooltip="{lb:s}",labeltooltip="{lb:s}"];\n'.format(bh=k, bhp=v[4], bht=v[3], tr=(t + 1), lb=lb)
                        else:
                            #
                            # Backhole not matched (Most likely: 'ICMP (3) destination-unreached'
                            # but last hop not equal to the target:
                            #
                            # Add this last Hop (This Hop is not the Target)...
                            #
                            # Check to skip in between traces...
                            if len(trace) > 1:
                                s += '\t{ptr:s} -> '.format(ptr=ntr)
                                lb = 'Trace: {tr:d}:{tn:d}, {lbp:s} -> {lbn:s}'.format(tr=(t + 1), tn=max(tk), lbp=ntr.replace('"', ''), lbn=lh)
                                lb += ' (RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms))'.format(prb=v[1], lbn=lh, rtt=self._rtt[t + 1][max(tk)])
                                llb = 'Trace: {tr:d}:{tn:d}, RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms)'.format(tr=(t + 1), tn=max(tk), prb=v[1], lbn=lh, rtt=self._rtt[t + 1][max(tk)])
                                if rtt:
                                    s += '"{lh:s} 3/icmp" [style="solid",label=<<FONT POINT-SIZE="8">&nbsp; {rtt:s}ms</FONT>>,edgetooltip="{lb:s}",labeltooltip="{llb:s}"];\n'.format(lh=lh, rtt=self._rtt[t + 1][max(tk)], lb=lb, llb=llb)
                                else:
                                    s += '"{lh:s} 3/icmp" [style="solid",edgetooltip="{lb:s} 3/icmp",labeltooltip="{llb:s}"];\n'.format(lh=lh, lb=lb, llb=llb)
                                #
                                # Add the Failed Target (Blackhole - Fake hop - never reached - use dashed trace)...
                                s += '\t"{lh:s} 3/icmp" -> '.format(lh=lh)
                            lb = 'Trace: {tr:d} - Failed MTR Resolved Target: {bh:s} {bhp:d}/{bht:s}'.format(tr=(t + 1), bh=k, bhp=v[4], bht=v[3])
                            s += '"{bh:s} {bhp:d}/{bht:s}" [style="dashed",label=<<FONT POINT-SIZE="8">&nbsp; T{tr:d}</FONT>>,edgetooltip="{lb:s}",labeltooltip="{llb:s}"];\n'.format(bh=k, bhp=v[4], bht=v[3], tr=(t + 1), lb=lb, llb=lb)

                    else:			# Enhanced Target Endpoint
                        #
                        # Check to skip in between traces...
                        if len(trace) > 1:
                            s += '\t{ptr:s} -> '.format(ptr=ntr)
                        lb = 'Trace: {tr:d}:{tn:d}, {lbp:s} -> {lbn:s}'.format(tr=(t + 1), tn=max(tk), lbp=ntr.replace('"', ''), lbn=k)
                        if not 'Unk' in k:
                            lb += ' (RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms))'.format(prb=v[1], lbn=k, rtt=self._rtt[t + 1][max(tk)])
                        pre = ''
                        if k in uepprb:		# Special Case: Distinguish the Endpoint Target from Probe
                            pre = '_'		# when they are the same using the underscore char: '_'.
                        if rtt:
                            if not 'Unk' in k:
                                llb = 'Trace: {tr:d}:{tn:d}, RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms)'.format(tr=(t + 1), tn=max(tk), prb=v[1], lbn=k, rtt=self._rtt[t + 1][max(tk)])
                                #
                                # Check to remove label clashing...
                                ntrs = ntr.replace('"', '')		# Remove surrounding double quotes ("")
                                if ntrs == k:
                                    s += '"{pre:s}{ep:s}":E{tr:s}:n [style="solid",xlabel=<<FONT POINT-SIZE="8">&nbsp; {rtt:s}ms</FONT>>,forcelabel=True,edgetooltip="{lb:s}",labeltooltip="{llb:s}"];\n'.format(pre=pre, ep=k, tr=v[0], rtt=self._rtt[t + 1][max(tk)], lb=lb, llb=llb)
                                else:
                                    s += '"{pre:s}{ep:s}":E{tr:s}:n [style="solid",label=<<FONT POINT-SIZE="8">&nbsp; {rtt:s}ms</FONT>>,edgetooltip="{lb:s}",labeltooltip="{llb:s}"];\n'.format(pre=pre, ep=k, tr=v[0], rtt=self._rtt[t + 1][max(tk)], lb=lb, llb=llb)
                            else:
                                s += '"{pre:s}{ep:s}":E{tr:s}:n [style="solid",edgetooltip="{lb:s}"];\n'.format(pre=pre, ep=k, tr=v[0], lb=lb)
                        else:
                            s += '"{pre:s}{ep:s}":E{tr:s}:n [style="solid",edgetooltip="{lb:s}"];\n'.format(pre=pre, ep=k, tr=v[0], lb=lb)
                t += 1				# Next trace out of total traces

        #
        # Decorate Unknown ('Unkn') Nodes...
        s += "\n\t### Decoration For Unknown (Unkn) Node Hops ###\n"
        for u in self._unks:
            s += '\t{u:s} [tooltip="Trace: {t:s}, Unknown Hop: {u2:s}",shape="egg",fontname="Sans-Serif",fontsize=9,height=0.2,width=0.2,color="black",gradientangle=270,fillcolor="white:#d8d8d8",style="filled"];\n'.format(u=u, t=self._unks[u][2], u2=u.replace('"', ''))

        #
        # Create tooltip for standalone nodes...
        s += "\n\t### Tooltip for Standalone Node Hops ###\n"
        for k, v in self._ips.items():
            if not k in cipall:
                if k != self._gw:
                    if not k in cepipall:
                        if not k in self._ports:
                            found = False
                            for tid in self._tlblid:
                                if k in tid:
                                    found = True
                                    break
                            if not found:
                                s += '\t"{ip:s}" [tooltip="Hop Host: {ip:s}"];\n'.format(ip=k)
        #
        # End the DOT Digraph...
        s += "}\n"
        #
        # Store the DOT Digraph results...
        self._graphdef = s

    #
    # Graph the Multi-Traceroute...
    def graph(self, ASres=None, padding=0, vspread=0.75, title="Multi-Traceroute Probe (MTR)", timestamp="", rtt=1, **kargs):
        """x.graph(ASres=conf.AS_resolver, other args):
        ASres = None          : Use AS default resolver => 'conf.AS_resolver'
        ASres = AS_resolver() : default whois AS resolver (riswhois.ripe.net)
        ASres = AS_resolver_cymru(): use whois.cymru.com whois database
        ASres = AS_resolver(server="whois.ra.net")
        padding: Show packets with padding as a red 3D-Box.
        vspread: Vertical separation between nodes on graph.
        title: Title text for the rendering graphic.
        timestamp: Title Time Stamp text to appear below the Title text.
        rtt: Display Round-Trip Times (msec) for Hops along trace edges.
        format: Output type (svg, ps, gif, jpg, etc.), passed to dot's "-T" option.
        figsize: w,h tuple in inches. See matplotlib documentation.
        target: filename. If None, uses matplotlib to display.
        prog: Which graphviz program to use."""
        if self._asres is None:
            self._asres = conf.AS_resolver
        if (self._graphdef is None or		# Remake the graph if there are any changes
            self._graphasres != self._asres or
                self._graphpadding != padding):
            self.make_dot_graph(ASres, padding, vspread, title, timestamp, rtt)

        return do_graph(self._graphdef, **kargs)

##################################
# Multi-Traceroute Results Class #
##################################


class MTracerouteResult(SndRcvList):
    def __init__(self, res=None, name="MTraceroute", stats=None):
        PacketList.__init__(self, res, name, stats, vector_index=1)

    def show(self, ntrace):
        return self.make_table(lambda s, r:
                               (s.sprintf("Trace: " + str(ntrace) + " - %IP.dst%:{TCP:tcp%ir,TCP.dport%}{UDP:udp%ir,UDP.dport%}{ICMP:ICMP}"),
                                s.ttl,
                                r.sprintf("%-15s,IP.src% {TCP:%TCP.flags%}{ICMP:%ir,ICMP.type%}")))

    #
    # Get trace components...
    #
    #   mtrc - Instance of a MTRC class
    #
    #     nq - Traceroute query number
    def get_trace_components(self, mtrc, nq):
        ips = {}
        rt = {}
        rtt = {}
        trtt = {}
        ports = {}
        portsdone = {}
        trgttl = {}
        if len(self.res) > 0:
            #
            # Responses found...
            for s, r in self.res:
                s = s.getlayer(IP) or (conf.ipv6_enabled and s[kamene.layers.inet6.IPv6]) or s
                r = r.getlayer(IP) or (conf.ipv6_enabled and r[kamene.layers.inet6.IPv6]) or r
                #
                # Make sure 'r.src' is an IP Address (e.g., Case where r.src = '24.97.150.188 80/tcp')
                rs = r.src.split()
                ips[rs[0]] = None
                if TCP in s:
                    trace_id = (s.src, s.dst, 6, s.dport)
                elif UDP in s:
                    trace_id = (s.src, s.dst, 17, s.dport)
                elif ICMP in s:
                    trace_id = (s.src, s.dst, 1, s.type)
                else:
                    trace_id = (s.src, s.dst, s.proto, 0)
                trace = rt.get(trace_id, {})
                ttl = conf.ipv6_enabled and kamene.layers.inet6.IPv6 in s and s.hlim or s.ttl
                #
                # Check for packet response types:
                if not (ICMP in r and r[ICMP].type == 11) and not (conf.ipv6_enabled and kamene.layers.inet6.IPv6 in r and kamene.layers.inet6.ICMPv6TimeExceeded in r):
                    #
                    # Mostly: Process target reached or ICMP Unreachable...
                    if trace_id in portsdone:
                        #
                        # Special check for out or order response packets: If previous trace was determined
                        # done, but a ttl arrives with a lower value then process this response packet as the
                        # final ttl target packet.
                        if ttl >= trgttl[trace_id]:
                            continue			# Next Send/Receive packet
                        else:
                            #
                            # Out of order response packet - process this packet as the possible
                            # final ttl target packet.
                            try:
                                if trgttl[trace_id] in trace:
                                    del trace[trgttl[trace_id]]		# Remove previous ttl target
                            except:
                                pass
                    portsdone[trace_id] = None
                    trgttl[trace_id] = ttl		# Save potential target ttl packet
                    p = ports.get(r.src, [])
                    if TCP in r:
                        p.append(r.sprintf("<T%ir,TCP.sport%> %TCP.sport% %TCP.flags%"))
                        trace[ttl] = r.sprintf('"%r,src%":T%ir,TCP.sport%')
                    elif UDP in r:
                        p.append(r.sprintf("<U%ir,UDP.sport%> %UDP.sport%"))
                        trace[ttl] = r.sprintf('"%r,src%":U%ir,UDP.sport%')
                    elif ICMP in r:
                        if r[ICMP].type == 0:
                            #
                            # Process echo-reply...
                            p.append(r.sprintf("<I%ir,ICMP.type%> ICMP %ICMP.type%"))
                            trace[ttl] = r.sprintf('"%r,src%":I%ir,ICMP.type%')
                        else:
                            #
                            # Format Ex: '<I3> ICMP dest-unreach port-unreachable 17 53'
                            p.append(r.sprintf("<I%ir,ICMP.type%> ICMP %ICMP.type% %ICMP.code% %ICMP.proto% %r,ICMP.dport%"))
                            trace[ttl] = r.sprintf('"%r,src%":I%ir,ICMP.type%')
                    else:
                        p.append(r.sprintf("{IP:<P%ir,proto%> IP %proto%}{IPv6:<P%ir,nh%> IPv6 %nh%}"))
                        trace[ttl] = r.sprintf('"%r,src%":{IP:P%ir,proto%}{IPv6:P%ir,nh%}')
                    ports[r.src] = p
                else:
                    #
                    # Mostly ICMP Time-Exceeded packet - Save Hop Host IP Address...
                    trace[ttl] = r.sprintf('"%r,src%"')
                rt[trace_id] = trace
                #
                # Compute the Round Trip Time for this trace packet in (msec)...
                rtrace = rtt.get(trace_id, {})
                crtt = (r.time - s.sent_time) * 1000
                rtrace[ttl] = "{crtt:.3f}".format(crtt=crtt)
                rtt[trace_id] = rtrace
        else:
            #
            # No Responses found - Most likely target same as host running the mtr session...
            #
            # Create a 'fake' failed target (Blackhole) trace using the destination host
            # found in unanswered packets...
            for p in mtrc._ures[nq]:
                ips[p.dst] = None
                trace_id = (p.src, p.dst, p.proto, p.dport)
                portsdone[trace_id] = None
                if trace_id not in rt:
                    pt = mtrc.get_proto_name(p.proto)
                    #
                    # Set trace number to zero (0) (i.e., ttl = 0) for this special case:
                    # target = mtr session host - 'fake' failed target...
                    rt[trace_id] = {1: '"{ip:s} {pr:d}/{pt:s}"'.format(ip=p.dst, pr=p.dport, pt=pt)}
        #
        # Store each trace component...
        mtrc._ips.update(ips)			# Add unique IP Addresses
        mtrc._rt.append(rt)			# Append a new Traceroute
        mtrc._ports.update(ports)		# Append completed Traceroute target and port info
        mtrc._portsdone.update(portsdone)  # Append completed Traceroute with associated target and port
        #
        # Create Round Trip Times Trace lookup dictionary...
        tcnt = mtrc._tcnt
        for rttk in rtt:
            tcnt += 1
            trtt[tcnt] = rtt[rttk]
            mtrc._rtt.update(trtt)  # Update Round Trip Times for Trace Nodes
        #
        # Update the Target Trace Label IDs and Blackhole (Failed Target) detection...
        #
        #           rtk0               rtk1   rtk2  rtk3
        # Ex: {('10.222.222.10', '10.222.222.1', 6, 9980): {1: '"10.222.222.10":T9980'}}
        for rtk in rt:
            mtrc._tcnt += 1		# Compute the total trace count
            #
            # Derive flags from ports:
            # Ex: {'63.117.14.247': ['<T80> http SA', '<T443> https SA']}
            prtflgs = ports.get(rtk[1], [])
            found = False
            for pf in prtflgs:
                if mtrc._netprotocol == 'ICMP':
                    pat = '<I0>'				# ICMP: Create reg exp pattern
                else:
                    pat = '<[TU]{p:d}>'.format(p=rtk[3])  # TCP/UDP: Create reg exp pattern
                match = re.search(pat, pf)			# Search for port match
                if match:
                    found = True
                    s = pf.split(' ')
                    if len(s) == 3:
                        pn = s[1]  # Service Port name / ICMP
                        fl = s[2]  # TCP Flags / ICMP Type / Proto
                    elif len(s) == 2:
                        pn = s[1]  # Service Port name
                        fl = ''
                    else:
                        pn = ''
                        fl = ''
                    break
            ic = ''			# ICMP Destination not reachable flag
            if not found:		# Set Blackhole found - (fl -> 'BH')
                #
                # Set flag for last hop is a target and ICMP destination not reached flag set...
                trace = rt[rtk]
                tk = trace.keys()
                lh = trace[max(tk)]
                f = lh.find(':I3')		# Is hop an ICMP destination not reached node?
                if f >= 0:
                    lh = lh[0:f] 		# Strip off 'proto:port' -> '"100.41.207.244":I3'
                    lh = lh.replace('"', '')  # Remove surrounding double quotes ("")
                    if lh in mtrc._exptrg:  # Is last hop a target?
                        ic = 'I3'
                pn = ''
                fl = 'BH'
            #
            # Update the Target Trace Label ID:
            # Ex: {'63.117.14.247': ('T2', '10.222.222.10', '162.144.22.87', 6, 443, 'https', 'SA', '')}
            pt = mtrc.get_proto_name(rtk[2])
            tlid = {rtk[1]: ('T' + str(mtrc._tcnt), rtk[0], rtk[1], pt, rtk[3], pn, fl, ic)}
            mtrc._tlblid.append(tlid)

####################
# Multi-Traceroute #
####################


@conf.commands.register
def mtr(target, dport=80, minttl=1, maxttl=30, stype="Random", srcport=50000, iface=None, l4=None, filter=None, timeout=2, verbose=None, gw=None, netproto="TCP", nquery=1, ptype=None, payload=b'', privaddr=0, rasn=1, **kargs):
    """A Multi-Traceroute (mtr) command:
         mtr(target, [maxttl=30,] [dport=80,] [sport=80,] [minttl=1,] [maxttl=1,] [iface=None]
             [l4=None,] [filter=None,] [nquery=1,] [privaddr=0,] [rasn=1,] [verbose=conf.verb])

              stype: Source Port Type: "Random" or "Increment".
            srcport: Source Port. Default: 50000.
                 gw: IPv4 Address of the Default Gateway.
           netproto: Network Protocol (One of: "TCP", "UDP" or "ICMP").
             nquery: Number of Traceroute queries to perform.
              ptype: Payload Type: "Disable", "RandStr", "RandStrTerm" or "Custom".
            payload: A byte object for each packet payload (e.g., b'\x01A\x0f\xff\x00') for ptype: 'Custom'.
           privaddr: 0 - Default: Normal display of all resolved AS numbers.
                     1 - Do not show an associated AS Number bound box (cluster) on graph for a private IPv4 Address.
               rasn: 0 - Do not resolve AS Numbers - No graph clustering.
                     1 - Default: Resolve all AS numbers."""
    #
    # Initialize vars...
    trace = []			# Individual trace array
    #
    # Range check number of query traces
    if nquery < 1:
        nquery = 1
    #
    # Create instance of an MTR class...
    mtrc = MTR(nquery=nquery, target=target)
    #
    # Default to network protocol: "TCP" if not found in list...
    plist = ["TCP", "UDP", "ICMP"]
    netproto = netproto.upper()
    if netproto not in plist:
        netproto = "TCP"
    mtrc._netprotocol = netproto
    #
    # Default to source type: "Random" if not found in list...
    slist = ["Random", "Increment"]
    stype = stype.title()
    if stype not in slist:
        stype = "Random"
    if stype == "Random":
        sport = RandShort()  # Random
    elif stype == "Increment":
        if srcport != None:
            sport = IncrementalValue(start=(srcport - 1), step=1, restart=65535)  # Increment
    #
    # Default to payload type to it's default network protocol value if not found in list...
    pllist = ["Disabled", "RandStr", "RandStrTerm", "Custom"]
    if ptype is None or (not ptype in pllist):
        if netproto == "ICMP":
            ptype = "RandStr"		# ICMP: A random string payload to fill out the minimum packet size
        elif netproto == "UDP":
            ptype = "RandStrTerm"  # UDP: A random string terminated payload to fill out the minimum packet size
        elif netproto == "TCP":
            ptype = "Disabled"		# TCP: Disabled -> The minimum packet size satisfied - no payload required
    #
    # Set trace interface...
    if not iface is None:
        mtrc._iface = iface
    else:
        mtrc._iface = conf.iface
    #
    # Set Default Gateway...
    if not gw is None:
        mtrc._gw = gw
    #
    # Set default verbosity if no override...
    if verbose is None:
        verbose = conf.verb
    #
    # Only consider ICMP error packets and TCP packets with at
    # least the ACK flag set *and* either the SYN or the RST flag set...
    filterundefined = False
    if filter is None:
        filterundefined = True
        filter = "(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12)) or (tcp and (tcp[13] & 0x16 > 0x10))"
    #
    # Resolve and expand each target...
    ntraces = 0		# Total trace count
    exptrg = []		# Expanded targets
    for t in target:
        #
        # Use kamene's 'Net' function to expand target...
        et = [ip for ip in iter(Net(t))]
        exptrg.extend(et)
        #
        # Map Host Names to IP Addresses and store...
        if t in mtrc._host2ip:
            mtrc._host2ip[t].extend(et)
        else:
            mtrc._host2ip[t] = et
        #
        # Map IP Addresses to Host Names and store...
        for a in et:
            mtrc._ip2host[a] = t
    #
    # Store resolved and expanded targets...
    mtrc._exptrg = exptrg
    #
    # Traceroute each expanded target value...
    if l4 is None:
        #
        # Standard Layer: 3 ('TCP', 'UDP' or 'ICMP') tracing...
        for n in range(0, nquery):
            for t in exptrg:
                #
                # Execute a traceroute based on network protocol setting...
                if netproto == "ICMP":
                    #
                    # MTR Network Protocol: 'ICMP'
                    tid = 8				        # Use a 'Type: 8 - Echo Request' packet for the trace:
                    id = 0x8888					# MTR ICMP identifier: '0x8888'
                    seq = IncrementalValue(start=(minttl - 2), step=1, restart=-10)  # Use a Sequence number in step with TTL value
                    if filterundefined:
                        #
                        # Update Filter -> Allow for ICMP echo-request (8) and ICMP echo-reply (0) packet to be processed...
                        filter = "(icmp and (icmp[0]=8 or icmp[0]=0 or icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12))"
                    #
                    # Check payload types:
                    if ptype == 'Disabled':
                        a, b = sr(IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl)) / ICMP(type=tid, id=id, seq=seq),
                                  timeout=timeout, filter=filter, verbose=verbose, **kargs)
                    else:
                        if ptype == 'RandStr':
                            #
                            # Use a random payload string to full out a minimum size PDU of 46 bytes for each ICMP packet:
                            # Length of 'IP()/ICMP()' = 28, Minimum Protocol Data Unit (PDU) is = 46 -> Therefore a
                            # payload of 18 octets is required.
                            pload = RandString(size=18)
                        elif ptype == 'RandStrTerm':
                            pload = RandStringTerm(size=17, term=b'\n')  # Random string terminated
                        elif ptype == 'Custom':
                            pload = payload
                        #
                        # ICMP trace with payload...
                        a, b = sr(IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl)) / ICMP(type=tid, id=id, seq=seq) / Raw(load=pload),
                                  timeout=timeout, filter=filter, verbose=verbose, **kargs)
                elif netproto == "UDP":
                    #
                    # MTR Network Protocol: 'UDP'
                    if filterundefined:
                        filter += " or udp"			# Update Filter -> Allow for processing UDP packets
                    #
                    # Check payload types:
                    if ptype == 'Disabled':
                        a, b = sr(IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl)) / UDP(sport=sport, dport=dport),
                                  timeout=timeout, filter=filter, verbose=verbose, **kargs)
                    else:
                        if ptype == 'RandStr':
                            #
                            # Use a random payload string to full out a minimum size PDU of 46 bytes for each UDP packet:
                            # Length of 'IP()/UDP()' = 28, Minimum PDU is = 46 -> Therefore a payload of 18 octets is required.
                            pload = RandString(size=18)
                        elif ptype == 'RandStrTerm':
                            pload = RandStringTerm(size=17, term=b'\n')  # Random string terminated
                        elif ptype == 'Custom':
                            pload = payload
                        #
                        # UDP trace with payload...
                        a, b = sr(IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl)) / UDP(sport=sport, dport=dport) / Raw(load=pload),
                                  timeout=timeout, filter=filter, verbose=verbose, **kargs)
                else:
                    #
                    # Default MTR Network Protocol: 'TCP'
                    #
                    # Use some TCP options for the trace. Some firewalls will filter
                    # TCP/IP packets without the 'Timestamp' option set.
                    #
                    # Note: The minimum PDU size of 46 is statisfied with the use of TCP options.
                    #
                    # Use an integer encoded microsecond timestamp for the TCP option timestamp for each trace sequence.
                    uts = IntAutoMicroTime()
                    opts = [('MSS', 1460), ('NOP', None), ('NOP', None), ('Timestamp', (uts, 0)), ('NOP', None), ('WScale', 7)]
                    seq = RandInt()		# Use a random TCP sequence number
                    #
                    # Check payload types:
                    if ptype == 'Disabled':
                        a, b = sr(IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl)) / TCP(seq=seq, sport=sport, dport=dport, options=opts),
                                  timeout=timeout, filter=filter, verbose=verbose, **kargs)
                    else:
                        if ptype == 'RandStr':
                            pload = RandString(size=32)			# Use a 32 byte random string
                        elif ptype == 'RandStrTerm':
                            pload = RandStringTerm(size=32, term=b'\n')  # Use a 32 byte random string terminated
                        elif ptype == 'Custom':
                            pload = payload
                        #
                        # TCP trace with payload...
                        a, b = sr(IP(dst=[t], id=RandShort(),
                                     ttl=(minttl, maxttl)) / TCP(seq=seq, sport=sport, dport=dport, options=opts) / Raw(load=pload),
                                  timeout=timeout, filter=filter, verbose=verbose, **kargs)
                #
                # Create an 'MTracerouteResult' instance for each result packets...
                trace.append(MTracerouteResult(res=a.res))
                mtrc._res.append(a)		# Store Response packets
                mtrc._ures.append(b)		# Store Unresponse packets
                if verbose:
                    trace[ntraces].show(ntrace=(ntraces + 1))
                    print()
                ntraces += 1
    else:
        #
        # Custom Layer: 4 tracing...
        filter = "ip"
        for n in range(0, nquery):
            for t in exptrg:
                #
                # Run traceroute...
                a, b = sr(IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl)) / l4,
                          timeout=timeout, filter=filter, verbose=verbose, **kargs)
                trace.append(MTracerouteResult(res=a.res))
                mtrc._res.append(a)
                mtrc._ures.append(b)
                if verbose:
                    trace[ntraces].show(ntrace=(ntraces + 1))
                    print()
                ntraces += 1
    #
    # Store total trace run count...
    mtrc._ntraces = ntraces
    #
    # Get the trace components...
    # for n in range(0, ntraces):
    for n in range(0, mtrc._ntraces):
        trace[n].get_trace_components(mtrc, n)
    #
    # Compute any Black Holes...
    mtrc.get_black_holes()
    #
    # Compute Trace Hop Ranges...
    mtrc.compute_hop_ranges()
    #
    # Resolve AS Numbers...
    if rasn:
        mtrc.get_asns(privaddr)
        #
        # Try to guess ASNs for Traceroute 'Unkown Hops'...
        mtrc.guess_unk_asns()
    #
    # Debug: Print object vars at verbose level 8...
    if verbose == 8:
        print("mtrc._target (User Target(s)):")
        print("=======================================================")
        print(mtrc._target)
        print("\nmtrc._exptrg (Resolved and Expanded Target(s)):")
        print("=======================================================")
        print(mtrc._exptrg)
        print("\nmtrc._host2ip (Target Host Name to IP Address):")
        print("=======================================================")
        print(mtrc._host2ip)
        print("\nmtrc._ip2host (Target IP Address to Host Name):")
        print("=======================================================")
        print(mtrc._ip2host)
        print("\nmtrc._res (Trace Response Packets):")
        print("=======================================================")
        print(mtrc._res)
        print("\nmtrc._ures (Trace Unresponse Packets):")
        print("=======================================================")
        print(mtrc._ures)
        print("\nmtrc._ips (Trace Unique IPv4 Addresses):")
        print("=======================================================")
        print(mtrc._ips)
        print("\nmtrc._rt (Individual Route Traces):")
        print("=======================================================")
        print(mtrc._rt)
        print("\nmtrc._rtt (Round Trip Times (msecs) for Trace Nodes):")
        print("=======================================================")
        print(mtrc._rtt)
        print("\nmtrc._hops (Traceroute Hop Ranges):")
        print("=======================================================")
        print(mtrc._hops)
        print("\nmtrc._tlblid (Target Trace Label IDs):")
        print("=======================================================")
        print(mtrc._tlblid)
        print("\nmtrc._ports (Completed Targets & Ports):")
        print("=======================================================")
        print(mtrc._ports)
        print("\nmtrc._portsdone (Completed Trace Routes & Ports):")
        print("=======================================================")
        print(mtrc._portsdone)
        print("\nconf.L3socket (Layer 3 Socket Method):")
        print("=======================================================")
        print(conf.L3socket)
        print("\nconf.AS_resolver Resolver (AS Resolver Method):")
        print("=======================================================")
        print(conf.AS_resolver)
        print("\nmtrc._asns (AS Numbers):")
        print("=======================================================")
        print(mtrc._asns)
        print("\nmtrc._asds (AS Descriptions):")
        print("=======================================================")
        print(mtrc._asds)
        print("\nmtrc._unks (Unknown Hops IP Boundary for AS Numbers):")
        print("=======================================================")
        print(mtrc._unks)
        print("\nmtrc._iface (Trace Interface):")
        print("=======================================================")
        print(mtrc._iface)
        print("\nmtrc._gw (Trace Default Gateway IPv4 Address):")
        print("=======================================================")
        print(mtrc._gw)

    return mtrc


###########################
# Simple TCP client stack #
###########################
class TCP_client(Automaton):

    def parse_args(self, ip, port, *args, **kargs):
        self.dst = next(iter(Net(ip)))
        self.dport = port
        self.sport = random.randrange(0, 2**16)
        self.l4 = IP(dst=ip) / TCP(sport=self.sport, dport=self.dport, flags=0,
                                   seq=random.randrange(0, 2**32))
        self.src = self.l4.src
        self.swin = self.l4[TCP].window
        self.dwin = 1
        self.rcvbuf = ""
        bpf = "host %s  and host %s and port %i and port %i" % (self.src,
                                                                self.dst,
                                                                self.sport,
                                                                self.dport)

#        bpf=None
        Automaton.parse_args(self, filter=bpf, **kargs)

    def master_filter(self, pkt):
        return (IP in pkt and
                pkt[IP].src == self.dst and
                pkt[IP].dst == self.src and
                TCP in pkt and
                pkt[TCP].sport == self.dport and
                pkt[TCP].dport == self.sport and
                self.l4[TCP].seq >= pkt[TCP].ack and  # XXX: seq/ack 2^32 wrap up
                ((self.l4[TCP].ack == 0) or (self.l4[TCP].ack <= pkt[TCP].seq <= self.l4[TCP].ack + self.swin)))

    @ATMT.state(initial=1)
    def START(self):
        pass

    @ATMT.state()
    def SYN_SENT(self):
        pass

    @ATMT.state()
    def ESTABLISHED(self):
        pass

    @ATMT.state()
    def LAST_ACK(self):
        pass

    @ATMT.state(final=1)
    def CLOSED(self):
        pass

    @ATMT.condition(START)
    def connect(self):
        raise self.SYN_SENT()

    @ATMT.action(connect)
    def send_syn(self):
        self.l4[TCP].flags = "S"
        self.send(self.l4)
        self.l4[TCP].seq += 1

    @ATMT.receive_condition(SYN_SENT)
    def synack_received(self, pkt):
        if pkt[TCP].flags & 0x3f == 0x12:
            raise self.ESTABLISHED().action_parameters(pkt)

    @ATMT.action(synack_received)
    def send_ack_of_synack(self, pkt):
        self.l4[TCP].ack = pkt[TCP].seq + 1
        self.l4[TCP].flags = "A"
        self.send(self.l4)

    @ATMT.receive_condition(ESTABLISHED)
    def incoming_data_received(self, pkt):
        if not isinstance(pkt[TCP].payload, NoPayload) and not isinstance(pkt[TCP].payload, conf.padding_layer):
            raise self.ESTABLISHED().action_parameters(pkt)

    @ATMT.action(incoming_data_received)
    def receive_data(self, pkt):
        data = (bytes(pkt[TCP].payload))
        if data and self.l4[TCP].ack == pkt[TCP].seq:
            self.l4[TCP].ack += len(data)
            self.l4[TCP].flags = "A"
            self.send(self.l4)
            self.rcvbuf += data
            if pkt[TCP].flags & 8 != 0:  # PUSH
                self.oi.tcp.send(self.rcvbuf)
                self.rcvbuf = ""

    @ATMT.ioevent(ESTABLISHED, name="tcp", as_supersocket="tcplink")
    def outgoing_data_received(self, fd):
        raise self.ESTABLISHED().action_parameters(fd.recv())

    @ATMT.action(outgoing_data_received)
    def send_data(self, d):
        self.l4[TCP].flags = "PA"
        self.send(self.l4 / d)
        self.l4[TCP].seq += len(d)

    @ATMT.receive_condition(ESTABLISHED)
    def reset_received(self, pkt):
        if pkt[TCP].flags & 4 != 0:
            raise self.CLOSED()

    @ATMT.receive_condition(ESTABLISHED)
    def fin_received(self, pkt):
        if pkt[TCP].flags & 0x1 == 1:
            raise self.LAST_ACK().action_parameters(pkt)

    @ATMT.action(fin_received)
    def send_finack(self, pkt):
        self.l4[TCP].flags = "FA"
        self.l4[TCP].ack = pkt[TCP].seq + 1
        self.send(self.l4)
        self.l4[TCP].seq += 1

    @ATMT.receive_condition(LAST_ACK)
    def ack_of_fin_received(self, pkt):
        if pkt[TCP].flags & 0x3f == 0x10:
            raise self.CLOSED()


###################
# Reporting stuff #
###################

def report_ports(target, ports):
    """portscan a target and output a LaTeX table
report_ports(target, ports) -> string"""
    ans, unans = sr(IP(dst=target) / TCP(dport=ports), timeout=5)
    rep = "\\begin{tabular}{|r|l|l|}\n\\hline\n"
    for _, r in ans:
        if not r.haslayer(ICMP):
            if r.payload.flags == 0x12:
                rep += r.sprintf("%TCP.sport% & open & SA \\\\\n")
    rep += "\\hline\n"
    for _, r in ans:
        if r.haslayer(ICMP):
            rep += r.sprintf("%TCPerror.dport% & closed & ICMP type %ICMP.type%/%ICMP.code% from %IP.src% \\\\\n")
        elif r.payload.flags != 0x12:
            rep += r.sprintf("%TCP.sport% & closed & TCP %TCP.flags% \\\\\n")
    rep += "\\hline\n"
    for i in unans:
        rep += i.sprintf("%TCP.dport% & ? & unanswered \\\\\n")
    rep += "\\hline\n\\end{tabular}\n"
    return rep


def IPID_count(lst, funcID=lambda x: x[1].id, funcpres=lambda x: x[1].summary()):
    idlst = map(funcID, lst)
    idlst.sort()
    # classes = [idlst[0]]+map(lambda x:x[1],filter(lambda (x,y): abs(x-y)>50, map(lambda x,y: (x,y),idlst[:-1], idlst[1:])))
    classes = [idlst[0]] + list(map(lambda x: x[1], filter(lambda a: abs(a[0] - a[1]) > 50, map(lambda x, y: (x, y), idlst[:-1], idlst[1:]))))
    lst = map(lambda x: (funcID(x), funcpres(x)), lst)
    lst.sort()
    print("Probably %i classes:" % len(classes), classes)
    for id, pr in lst:
        print("%5i" % id, pr)


def fragleak(target, sport=123, dport=123, timeout=0.2, onlyasc=0):
    load = "XXXXYYYYYYYYYY"
#    getmacbyip(target)
#    pkt = IP(dst=target, id=RandShort(), options="\x22"*40)/UDP()/load
    pkt = IP(dst=target, id=RandShort(), options="\x00" * 40, flags=1) / UDP(sport=sport, dport=sport) / load
    s = conf.L3socket()
    intr = 0
    found = {}
    try:
        while 1:
            try:
                if not intr:
                    s.send(pkt)
                sin, _, _ = select([s], [], [], timeout)
                if not sin:
                    continue
                ans = s.recv(1600)
                if not isinstance(ans, IP):  # TODO: IPv6
                    continue
                if not isinstance(ans.payload, ICMP):
                    continue
                if not isinstance(ans.payload.payload, IPerror):
                    continue
                if ans.payload.payload.dst != target:
                    continue
                if ans.src != target:
                    print("leak from", ans.src, end=" ")


#                print repr(ans)
                if not ans.haslayer(conf.padding_layer):
                    continue


#                print repr(ans.payload.payload.payload.payload)

#                if not isinstance(ans.payload.payload.payload.payload, conf.raw_layer):
#                    continue
#                leak = ans.payload.payload.payload.payload.load[len(load):]
                leak = ans.getlayer(conf.padding_layer).load
                if leak not in found:
                    found[leak] = None
                    linehexdump(leak, onlyasc=onlyasc)
            except KeyboardInterrupt:
                if intr:
                    raise
                intr = 1
    except KeyboardInterrupt:
        pass


def fragleak2(target, timeout=0.4, onlyasc=0):
    found = {}
    try:
        while 1:
            p = sr1(IP(dst=target, options="\x00" * 40, proto=200) / "XXXXYYYYYYYYYYYY", timeout=timeout, verbose=0)
            if not p:
                continue
            if conf.padding_layer in p:
                leak = p[conf.padding_layer].load
                if leak not in found:
                    found[leak] = None
                    linehexdump(leak, onlyasc=onlyasc)
    except:
        pass


conf.stats_classic_protocols += [TCP, UDP, ICMP]
conf.stats_dot11_protocols += [TCP, UDP, ICMP]

if conf.ipv6_enabled:
    import kamene.layers.inet6
