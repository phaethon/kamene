# kamene (formerly known as "scapy for python3" or scapy3k) 

## Important announcement

To clearly separate from original scapy project and decrease ambiguity in naming, we are undergoing renaming. This will include:
* renaming of the github repo (done)
* using new package name on PyPI (first release published, consider it for testing purposes at this moment)
* new python module name (done)
* documentation to be updated (not fully done yet, including this Readme)

Existing PyPI package scapy-python3 will not be updated with new functionality except a warning message on the need to transition to a different package.

N.B.! If you use current code from Github or new package kamene from PyPI you need to use `from kamene.all import *` (instead of `from scapy.all import *`).

More news to follow on the coming new features once naming transition is finalized. 

## General

[Follow @pkt_kamene](https://twitter.com/pkt_kamene) for recent news. [Original scapy documentation updated for scapy3k](http://kamene.readthedocs.io/en/latest/)

This is a fork of scapy (http://www.secdev.org) originally developed to implement python3 compatibility. It has been used in production on python3 since 2015 (while secdev/scapy implemented python3 compatibility in 2018).

All tests from regression (758 tests), ipsec, and both other test suites pass. Also, I tested full tutorial series [Building Network Tools with Scapy by @thepacketgeek](http://thepacketgeek.com/series/building-network-tools-with-scapy/) using scapy-python3.
Please, submit all issues https://github.com/phaethon/kamene preferrably with .pcap files for tests. Bugs for individual layers are usually easy to fix.

[winpcapy.py by Massimo Ciani](https://code.google.com/p/winpcapy/) integrated inside code.

## News

We are undergoing major naming transition, which will be followed with new functionality. More updates to follow.

Kamene is included in the [Network Security Toolkit](http://www.networksecuritytoolkit.org/nst/index.html) Release 28. It used to be included in NST since Release 22 under former name.

These features were first implemented in kamene and some of them might have been reimplemented in scapy by now:
* replaced PyCrypto with cryptography.io (thanks to @ThomasFaivre)
* Windows support without a need for libdnet
* option to return Networkx graphs instead of image, e.g. for conversations
* replaced gnuplot with Matplotlib
* Reading PCAP Next Generation (PCAPNG) files (please, add issues on GitHub for block types and options, which need support. Currently, reading packets only from Enhanced Packet Block)
* new command tdecode to call tshark decoding on one packet and display results, this is handy for interactive work and debugging
* python3 support
* some bugs fixed, which are still present in original scapy

## Installation

Install with `python3 setup.py install` from source tree (get it with `git clone https://github.com/phaethon/kamene.git`) or `pip3 install kamene` for latest published version.

On all OS except Linux libpcap should be installed for sending and receiving packets (not python modules - just C libraries) or winpcap driver on Windows. On some OS and configurations installing libdnet may improve experience (for MacOS: `brew install libdnet`). On Windows libdnet is not required. On some less common configurations netifaces may improve experience.

## Usage

*N.B.! As a difference from scapy for python2, use `bytes()` instead of `str()` when converting packet to bytes. Also, most arguments expect `bytes` value instead of `str `value except the ones, which are naturally suited for human input (e.g. domain name).*

You can use kamene running `kamene` command or by importing kamene as library from interactive python shell (python or ipython) or code.
Simple example that you can try from interactive shell:
```python
from kamene import *
p = IP(dst = 'www.somesite.ex') / TCP(dport = 80) / Raw(b'Some raw bytes')
# to see packet content as bytes use bytes(p) not str(p)
sr1(p)
```
Notice `'www.somesite.ex'` as a string, and `b'Some raw bytes'` as bytes. Domain name is normal human input, thus it is string, raw packet content is byte data. Once you start using, it will seem easier than it looks.

Use `ls()` to list all supported layers. Use `lsc()` to list all commands.

## Compatibility

All commands listed by `lsc()` should work. Tested layers are:
* ARP
* DHCP
* DHCPv6
* DNS
* DoIP
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
* RadioTap
* Raw
* SCTP
* SNAP
* SNMP
* STP
* TCP
* TFTP
* UDP

Currently, works on Linux, Darwin, Unix and co. Using python 3.4 on Ubuntu and FreeBSD for testing. Windows support in progress.

Compatible with [scapy-http module](https://github.com/invernizzi/scapy-http)

## Short cookbook

### Reading huge pcap file
rdpcap reads whole pcap file into memory. If you need to process huge file and perform some operation per packet or calculate some statistics, you can use PcapReader with iterator interface.

```python
with PcapReader('filename.pcap') as pcap_reader:
  for pkt in pcap_reader:
    #do something with the packet
```

<a href="https://koding.com/"> <img src="https://koding-cdn.s3.amazonaws.com/badges/made-with-koding/v1/koding_badge_ReadmeLight.png" srcset="https://koding-cdn.s3.amazonaws.com/badges/made-with-koding/v1/koding_badge_ReadmeLight.png 1x, https://koding-cdn.s3.amazonaws.com/badges/made-with-koding/v1/koding_badge_ReadmeLight@2x.png 2x" alt="Made with Koding" /> </a>
