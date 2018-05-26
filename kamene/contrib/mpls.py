# http://trac.secdev.org/scapy/ticket/31 

# kamene.contrib.description = MPLS
# kamene.contrib.status = loads

from kamene.packet import Packet,bind_layers
from kamene.fields import BitField,ByteField
from kamene.layers.l2 import Ether

class MPLS(Packet): 
   name = "MPLS" 
   fields_desc =  [ BitField("label", 3, 20), 
                    BitField("cos", 0, 3), 
                    BitField("s", 1, 1), 
                    ByteField("ttl", 0)  ] 

bind_layers(Ether, MPLS, type=0x8847)
