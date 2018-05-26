
# http://trac.secdev.org/scapy/ticket/297

# kamene.contrib.description = EtherIP
# kamene.contrib.status = loads

from kamene.fields import BitField
from kamene.packet import Packet, bind_layers
from kamene.layers.inet import IP
from kamene.layers.l2 import Ether

class EtherIP(Packet):
    name = "EtherIP / RFC 3378"
    fields_desc = [ BitField("version", 3, 4),
                    BitField("reserved", 0, 12)]

bind_layers( IP,            EtherIP,       frag=0, proto=0x61)
bind_layers( EtherIP,       Ether)

