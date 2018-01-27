## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
GPRS (General Packet Radio Service) for mobile data communication.
"""

from scapy3k.fields import *
from scapy3k.packet import *
from scapy3k.layers.inet import IP

class GPRS(Packet):
    name = "GPRSdummy"
    fields_desc = [
        StrStopField("dummy","","\x65\x00\x00",1)
        ]


bind_layers( GPRS,          IP,            )
