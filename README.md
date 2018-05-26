# kamene (formerly known as "scapy for python3" or scapy3k) 

## Important announcement

To clearly separate from original scapy project and decrease ambiguity in naming, we are undergoing renaming. This will include:
* renaming of the github repo (done)
* using new package name on PyPI (at present only non functional package as a placeholder is published, do not use it yet)
* new python module name (renaming currently in development)
* documentation to be updated (not done yet, including this Readme)

Existing PyPI package scapy-python3 will not be updated with new functionality except a warning message on the need to transition to the different package.

N.B.! If you use current code from Github you need to use `from scapy3k.all import *` (instead of `from scapy.all import *`).
This is temporary solution to resolve name clashes. From the next release you will need to use `from kamene.all import *`.

More news to follow on the coming new features once naming transition is finalized. 

## General

[Follow @scapy3k](https://twitter.com/scapy3k) and/or see [scapy3k news and examples](https://phaethon.github.io/scapy) for recent news. [Original scapy documentation updated for scapy3k](http://phaethon.github.io/scapy/api/index.html)

This is a fork of scapy (http://www.secdev.org) originally developed to implement python3 compatibility. It has been used in production on python3 since 2015.

All tests from regression (758 tests), ipsec, and both other test suites pass. Also, I tested full tutorial series [Building Network Tools with Scapy by @thepacketgeek](http://thepacketgeek.com/series/building-network-tools-with-scapy/) using scapy-python3.
Please, submit all issues https://github.com/phaethon/scapy preferrably with .pcap files for tests. Bugs for individual layers are usually easy to fix.

[winpcapy.py by Massimo Ciani](https://code.google.com/p/winpcapy/) integrated inside code.

## News

We are undergoing major naming transition, which will be followed with new functionality. More updates to follow.

[Follow @scapy3k](https://twitter.com/scapy3k) and/or see [scapy3k](https://phaethon.github.io/scapy) for recent news.

Scapy3k is included in the [Network Security Toolkit](http://www.networksecuritytoolkit.org/nst/index.html) Release 22. 

Classic scapy has been trying to catch up with the improvements in scapy3k. These features were first implemented in scapy3k and some of them might have been reimplemented in scapy or not:
* replaced PyCrypto with cryptography.io (thanks to @ThomasFaivre)
* Windows support without a need for libdnet
* option to return Networkx graphs instead of image, e.g. for conversations
* replaced gnuplot with Matplotlib
* Reading PCAP Next Generation (PCAPNG) files (please, add issues on GitHub for block types and options, which need support. Currently, reading packets only from Enhanced Packet Block)
* new command tdecode to call tshark decoding on one packet and display results, this is handy for interactive work and debugging
* some bugs fixed, which are still present in original scapy

## Installation

Install with `python3 setup.py install` from source tree (get it with `git clone https://github.com/phaethon/scapy.git`) or `pip3 install scapy-python3` for latest published version.

On all OS except Linux libpcap should be installed for sending and receiving packets (not python modules - just C libraries) or winpcap driver on Windows. On some OS and configurations installing libdnet may improve experience (for MacOS: `brew install libdnet`). On Windows libdnet is not required. On some less common configurations netifaces may improve experience.

## Usage

*N.B.! As a difference from scapy for python2, use `bytes()` instead of `str()` when converting packet to bytes. Also, most arguments expect `bytes` value instead of `str `value except the ones, which are naturally suited for human input (e.g. domain name).*

You can use scapy running scapy3k command or by importing scapy3k library from interactive python shell (python or ipython).
Simple example that you can try from interactive shell:
```python
from scapy3k.all import *
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

More examples will be posted at [scapy3k](https://phaethon.github.io/scapy)

### Reading huge pcap file
rdpcap reads whole pcap file into memory. If you need to process huge file and perform some operation per packet or calculate some statistics, you can use PcapReader with iterator interface.

```python
with PcapReader('filename.pcap') as pcap_reader:
  for pkt in pcap_reader:
    #do something with the packet
```

<a href="https://koding.com/"> <img src="https://koding-cdn.s3.amazonaws.com/badges/made-with-koding/v1/koding_badge_ReadmeLight.png" srcset="https://koding-cdn.s3.amazonaws.com/badges/made-with-koding/v1/koding_badge_ReadmeLight.png 1x, https://koding-cdn.s3.amazonaws.com/badges/made-with-koding/v1/koding_badge_ReadmeLight@2x.png 2x" alt="Made with Koding" /> </a>
