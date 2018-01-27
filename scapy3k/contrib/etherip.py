
# http://trac.secdev.org/scapy/ticket/297

# scapy3k.contrib.description = EtherIP
# scapy3k.contrib.status = loads

from scapy3k.fields import BitField
from scapy3k.packet import Packet, bind_layers
from scapy3k.layers.inet import IP
from scapy3k.layers.l2 import Ether

class EtherIP(Packet):
    name = "EtherIP / RFC 3378"
    fields_desc = [ BitField("version", 3, 4),
                    BitField("reserved", 0, 12)]

bind_layers( IP,            EtherIP,       frag=0, proto=0x61)
bind_layers( EtherIP,       Ether)

