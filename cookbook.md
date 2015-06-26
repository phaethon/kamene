---
layout: page
title: Cookbook
permalink: /cookbook/
---
{% for post in site.posts %}
  {% if post.title %}
  <a class="page-link" href="{{ post.url | prepend: site.baseurl }}">{{ post.title }}</a>
  {% endif %}
{% endfor %}

