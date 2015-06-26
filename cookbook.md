---
layout: page
title: Cookbook
permalink: /cookbook/
---
Cookbook examples assume special meaning for these variable names:

* *pkt* single packet created by user or sniffed from the network
* *packets* list of packets (e.g. PacketList sniffed with `sniff`)

Additional examples in [API documentation]({{ "/api/" | prepend: site.baseurl }})

{% for post in site.posts %}
  {% if post.title %}
  <a class="page-link" href="{{ post.url | prepend: site.baseurl }}">{{ post.title }}</a>
  {% endif %}
{% endfor %}

