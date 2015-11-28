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

On all OS except Linux libpcap (winpcap on Windows) should be installed for sending and receiving packets (not python modules - just C libraries). libdnet is recommended for Darwin, FreeBSD, Unix. Windows does not require libdnet. If running into issues with routes and interface detection, netifaces module installation can sometimes help, but otherwise is not required.

## Basic usage

*N.B.! As a difference from scapy for python2, use bytes() instead of str() when converting packet to bytes. Also, most arguments expect bytes value instead of str value except the ones, which are naturally suited for human input (e.g. domain name).*

You can use scapy running scapy command or by importing scapy library from interactive python shell (python or ipython).
Simple example that you can try from interactive shell:
{% highlight python %}
from scapy.all import *
p = IP(dst = 'www.somesite.ex') / TCP(dport = 80) / Raw(b'Some raw bytes')
# to see packet content as bytes use bytes(p) not str(p)
sr1(p)
{% endhighlight %}
Notice `'www.somesite.ex'` as a string, and `b'Some raw bytes'` as bytes. Domain name is normal human input, thus it is string, raw packet content is byte data. Once you start using, it will seem easier than in looks.

Use ls() to list all supported layers. Use lsc() to list all commands.

Additional examples in [API documentation]({{ "/api/" | prepend: site.baseurl }})

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

Currently, works on Windows (8/2012 and up), Linux, Darwin, Unix and co. Using python 3.4 on Ubuntu and FreeBSD for testing. Using Windows 10/Anaconda 3.5/WinPcap 4.1.3 for testing on Windows.
