---
layout: page
title: Getting started
permalink: /getting-started/
---
## Installation

Install from source using:
{% highlight bash %}
git clone https://github.com/phaethon/scapy.git
cd scapy
python3 setup.py install
{% endhighlight %}

or `pip3 install scapy-python3` for latest published package version.

On all OS except Linux libpcap should be installed for sending and receiving packets (not python modules - just C libraries). libdnet is recommended for sending packets, without libdnet packets will be sent by libpcap, which is limited. Also, netifaces module can be used for alternative and possibly cleaner way to determine local addresses.

## Basic usage

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