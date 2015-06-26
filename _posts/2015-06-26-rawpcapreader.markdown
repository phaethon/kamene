---
layout: post
title:  "Reading a huge PCAP or PCAPNG file"
date:   2015-06-26 14:37:54
categories: cookbook
---
When you read PCAP file with rdpcap, the full list of decoded packets is saved in memory.   If you need to do some processing per packet and do not need the full list then it is much more memory efficient to use RawPcapReader packet generator like this:

{% highlight python %}
with PcapReader('filename.pcapng') as pcap_reader:
  for pkt in pcap_reader:
    #do something with the packet
    ...
{% endhighlight %}