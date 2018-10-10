# kamene (formerly known as "scapy for python3" or scapy3k) 

## General

[Follow @pkt_kamene](https://twitter.com/pkt_kamene) for recent news. [Original documentation updated for kamene](http://kamene.readthedocs.io/en/latest/)

## News

We underwent naming transition (of github repo, pip package name, and python package name), which will be followed by new functionality. More updates to follow.

Kamene is included in the [Network Security Toolkit](http://www.networksecuritytoolkit.org/nst/index.html) Release 28. It used to be included in NST since Release 22 under former name.

## History

This is a fork of scapy (http://www.secdev.org) originally developed to implement python3 compatibility. It has been used in production on python3 since 2015 (while secdev/scapy implemented python3 compatibility in 2018). The fork was renamed to kamene in 2018 to reduce any confusion.

These features were first implemented in kamene and some of them might have been reimplemented in scapy by now:
* replaced PyCrypto with cryptography.io (thanks to @ThomasFaivre)
* Windows support without a need for libdnet
* option to return Networkx graphs instead of image, e.g. for conversations
* replaced gnuplot with Matplotlib
* Reading PCAP Next Generation (PCAPNG) files (please, add issues on GitHub for block types and options, which need support. Currently, reading packets only from Enhanced Packet Block)
* new command tdecode to call tshark decoding on one packet and display results, this is handy for interactive work and debugging
* python3 support

## Installation

Install with `python3 setup.py install` from source tree (get it with `git clone https://github.com/phaethon/kamene.git`) or `pip3 install kamene` for latest published version.

On all OS except Linux libpcap should be installed for sending and receiving packets (not python modules - just C libraries) or winpcap driver on Windows. On some OS and configurations installing libdnet may improve experience (for MacOS: `brew install libdnet`). On Windows libdnet is not required. On some less common configurations netifaces may improve experience.

## Usage

Use `bytes()` (not `str()`) when converting packet to bytes. Most arguments expect `bytes` value instead of `str `value except the ones, which are naturally suited for human input (e.g. domain name).*

You can use kamene running `kamene` command or by importing kamene as library from interactive python shell (python or ipython) or code.
Simple example that you can try from interactive shell:
```python
from kamene.all import *
p = IP(dst = 'www.somesite.ex') / TCP(dport = 80) / Raw(b'Some raw bytes')
# to see packet content as bytes use bytes(p) not str(p)
sr1(p)
```
Notice `'www.somesite.ex'` as a string, and `b'Some raw bytes'` as bytes. Domain name is normal human input, thus it is string, raw packet content is byte data. Once you start using, it will seem easier than it looks.

Use `ls()` to list all supported layers. Use `lsc()` to list all commands.

Currently, works on Linux, Darwin, Unix and co. Using python 3.4+ on Ubuntu, MacOS, FreeBSD, Windows 10 for testing.

Compatible with [scapy-http module](https://github.com/invernizzi/scapy-http)

### Reading huge pcap file
rdpcap reads whole pcap file into memory. If you need to process huge file and perform some operation per packet or calculate some statistics, you can use PcapReader with iterator interface.

```python
with PcapReader('filename.pcap') as pcap_reader:
  for pkt in pcap_reader:
    #do something with the packet
```
