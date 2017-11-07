#! /usr/bin/env python

## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Nils Weiss <nils@we155.de>
## This program is published under a GPLv2 license

"""
CANSocket.
"""

from scapy.packet import *
from scapy.fields import *
import scapy.sendrecv as sendrecv
from scapy.supersocket import SuperSocket
from scapy.arch.linux import get_last_packet_timestamp

############
## Consts ##
############
CAN_FRAME_SIZE = 16
LINKTYPE_CAN_SOCKETCAN = 227  # From pcap spec

class CAN(Packet):
    name = 'CAN'
    fields_desc = [
        FlagsField("flags", 0, 3, ["ERR", "RTR", "EFF"]),
        XBitField("id", 0, 29),
        PadField(FieldLenField('dlc', None, length_of='data', fmt='B'), 4),
        PadField(StrLenField('data', '', length_from=lambda pkt: min(pkt.dlc, 8)), 8)
    ]

    def extract_padding(self, p):
        return '', p

    def pre_dissect(self, s):
        # need to change the byteoder of the first four bytes
        return struct.pack('<I12s', *struct.unpack('>I12s', s))

    def post_build(self, pkt, pay):
        # need to change the byteoder of the first four bytes
        return struct.pack('<I12s', *struct.unpack('>I12s', pkt))+pay

class CANSocket(SuperSocket):
    desc = "read/write packets at a given CAN interface using PF_CAN sockets"
    can_frame_fmt = "<IB3x8s"

    def __init__(self, iface=None, receive_own_messages=False, filter=None, nofilter=0):
        if iface is None:
            iface = conf.CANiface
        self.ins = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)

        try:
            self.ins.setsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_RECV_OWN_MSGS,
                                struct.pack('i', receive_own_messages))
        except Exception as e:
            Scapy_Exception("Could not receive own messages (%s)", e)

        if filter is None or nofilter == 0:
            filter = [{
                'can_id': 0,
                'can_mask': 0
            }]

        can_filter_fmt = "={}I".format(2 * len(filter))
        filter_data = []
        for can_filter in filter:
            filter_data.append(can_filter['can_id'])
            filter_data.append(can_filter['can_mask'])

        self.ins.setsockopt(socket.SOL_CAN_RAW,
                            socket.CAN_RAW_FILTER,
                            struct.pack(can_filter_fmt, *filter_data)
                            )

        self.ins.bind((iface,))
        self.outs = self.ins

    def recv(self, x=CAN_FRAME_SIZE):
        # Fetching the Arb ID, DLC and Data
        try:
            pkt, sa_ll = self.ins.recvfrom(x)
        except BlockingIOError:
            warning('Captured no data, socket in non-blocking mode.')
            return None
        except socket.timeout:
            warning('Captured no data, socket read timed out.')
            return None
        except OSError:
            # something bad happened (e.g. the interface went down)
            warning("Captured no data.")
            return None

        q = CAN(pkt)
        q.time = get_last_packet_timestamp(self.ins)
        return q

    def sr(self, *args, **kargs):
        return sendrecv.sndrcv(self, *args, **kargs)
    def sr1(self, *args, **kargs):
        a,b = sendrecv.sndrcv(self, *args, **kargs)
        if len(a) > 0:
            return a[0][1]
        else:
            return None
    def sniff(self, *args, **kargs):
        return sendrecv.sniff(opened_socket=self, *args, **kargs)

@conf.commands.register
def srcan(pkt, iface=None, receive_own_messages=False, filter=None, nofilter=0, *args, **kargs):
    if not "timeout" in kargs:
        kargs["timeout"] = -1
    s = conf.CANSocket(iface, receive_own_messages, filter, nofilter)
    a, b = s.sr(pkt, *args, **kargs)
    s.close()
    return a, b

@conf.commands.register
def srcanloop(pkts, *args, **kargs):
    """Send a packet at can layer in loop and print the answer each time
srloop(pkts, [prn], [inter], [count], ...) --> None"""
    return sendrecv.__sr_loop(srcan, pkts, *args, **kargs)

conf.l2types.register(LINKTYPE_CAN_SOCKETCAN, CAN)
conf.CANiface = "can0"
conf.CANSocket = CANSocket
