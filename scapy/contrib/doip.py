#!/usr/bin/env python3

# scapy.contrib.description = DoIP
# scapy.contrib.status = loads

"""
Diagnostics over IP Extension
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This extension is a very basic implementation of `Diagnostics over IP (DoIP) <http://www.autosar.org/fileadmin/files/releases/4-2/software-architecture/diagnostic-services/standard/AUTOSAR_SWS_DiagnosticOverIP.pdf>`_,
an IP-based protocol used in automotive environments defined as
part of `AUTOSAR 4.2.2 <http://www.autosar.org/>`_.
This is pretty much a work in progress, so expect breaking changes.


:version: 0.1
:date: 2017-03-10
:author: tpltnt <tpltnt.scapy.doip@dropcut.net>

:Thanks:
- the two automotive people for nagging me
"""
from scapy.fields import ByteEnumField, IntField, StrLenField, XByteField, XShortEnumField
from scapy.layers.inet import TCP, UDP
from scapy.packet import Packet, bind_layers



# payload types according to table 3
payload_types = {0x0000: "generic DoIP header negative acknowledge",
                 0x0001: "vehicle identification request message",
                 0x0002: "vehicle identification request",
                 0x0003: "vehicle identification request message with VIN",
                 0x0004: "Vehicle announcement message/vehicle identification response",
                 0x0005: "routing activation request",
                 0x0006: "routing activation response",
                 0x0007: "alive check request",
                 0x0008: "alive check response",
                 0x4001: "DoIP entity status request",
                 0x4002: "DoIP entity status response",
                 0x4003: "diagnostic power mode information request",
                 0x4004: "diagnostic power mode information response",
                 0x8001: "diagnostic message",
                 0x8002: "Diagnostic message positive acknowledgement",
                 0x8003: "diagnostic message negative acknowledgement"}


class DoIPRawPacket(Packet):
    """
    This class models the a raw/generic Diagnositics over IP (DoIP) packet.
    The protocol version (inverse protocol version) are fixed to 0x02.
    The fields 'payload_type', 'payload_length' and 'payload_content'
    should be set according to the actual payload.

    Example of a generic acknowledge:
    >>> from scapy.contrib.doip import *
    >>> DoIP(payload_type=0x0000, payload_length=1, payload_content=b'\x02')
    <DoIP  payload_type=generic DoIP header negative acknowledge payload_length=1 payload_content='\x02' |>
    """
    name = "DoIPRaw"
    # field names are abbreviated to facilitate pretty printing etc.
    fields_desc = [XByteField("protocol_version", 0x02),
                   XByteField("inverse_version", 0xFD),
                   XShortEnumField("payload_type", 0, payload_types),
                   IntField("payload_length", 0),
                   StrLenField("payload_content", "", length_from=lambda pkt: pkt.payload_length)
                  ]

    def dissect(self, b):
        """
        Dissect an incoming DoIP packet.

        :param b: bytes to dissect
        :type b: bytes
        :raises: ValueError
        """
        if len(b) < 8:
            raise ValueError("given packet too short")
        return super(DoIPRawPacket, self).dissect(b)

# bind things together
bind_layers(UDP, DoIPRawPacket, sport=13400)
bind_layers(UDP, DoIPRawPacket, dport=13400)
bind_layers(TCP, DoIPRawPacket, sport=13400)
bind_layers(TCP, DoIPRawPacket, dport=13400)
