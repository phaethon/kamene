# scapy for python3 (aka scapy3k) 
This is a fork of scapy (http://www.secdev.org) to make it compatible with python3. Fork based on scapy v2.3.1
All tests from regression (758 tests), ipsec, and both other test suites pass. Also, I tested full tutorial series Building Network Tools with Scapy by @thepacketgeek (http://thepacketgeek.com/series/building-network-tools-with-scapy/) using scapy-python3.
Please, submit all issues https://github.com/phaethon/scapy preferrably with .pcap files for tests. Bugs for individual layers are usually easy to fix.

winpcapy.py by Massimo Ciani https://code.google.com/p/winpcapy/ integrated inside code

## Installation
Install with 'python3 setup.py install' from source tree (get it with `git clone https://github.com/phaethon/scapy.git`) or `pip3 install scapy-python3` for latest published version.

## Usage

*N.B.! As a difference from scapy for python2, use bytes() instead of str() for most cases. Also, most arguments expect bytes value instead of str value.*

You can use scapy running scapy command or by importing scapy library from interactive python shell (python or preferrably ipython).
Simple example that you can try from interactive shell:
```python
from scapy.all import *
p = IP(dst = 'www.google.com') / TCP(dport = 80) / Raw(b'GET / HTTP/1.0')
sr1(p)
```
Notice `'www.google.com'` as a string, and `b'GET / HTTP/1.0' as bytes. Domain name is normal human input, thus it is string, raw packet content is byte data. Once you start using, it will seem more easy than in looks. Also, notice bytes are returned in the answer.

## Compatibility

All commands listed by lsc() should work. Tested layers are:
* ARP
* DHCP
* DHCPv6
* DNS
* Dot3
* Dot11
* Ether
* ICMP
* ICMPv6
* IP
* IPv6
* LLC
* NTP
* Padding
* PPP
* Raw
* SCTP
* SNAP
* SNMP
* STP
* TCP
* TFTP
* UDP

Currently, works on Linux, Darwin, Unix and co. Using python 3.4 on Ubuntu and FreeBSD for testing. Windows support in progress.

On all OS except Linux libpcap should be installed for sending and receiving packets (not python modules - just C libraries). libdnet is recommended for sending packets, without libdnet packets will be sent by libpcap, which is limited. Also, netifaces module can be used for alternative and possibly cleaner way to determine local addresses.

## Short cookbook

### Reading huge pcap file
rdpcap reads whole pcap file into memory. If you need to process huge file and perform some operation per packet or calculate some statistics, you can use PcapReader with iterator interface.

```python
with PcapReader('filename.pcap') as pcap_reader:
  for pkt in pcap_reader:
    #do something with the packet
