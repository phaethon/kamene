#!/usr/bin/env python
# encoding: utf-8

# load me using load_module
# load_module("bzdump")

import sys
import os

try:
    import Image# install PIL
except ImportError:
    from PIL import Image# install PIL

from scapy.plist import PacketList

# http://yak-shaver.blogspot.jp/2013/08/blog-post.html
def split_str(s, n):
    "split string by its length"
    length = len(s)
    return [s[i:i+n] for i in range(0, length, n)]

palette8bit = [ b | (g<<8) | (r<<16) for b in range(0x0, 0x100, 0x33) for g in range(0x0, 0x100, 0x33) for r in range(0x0, 0x100, 0x33)] + [gr for gr in range(0x0, 0x1000000, 0x111111)] + [0xC0C0C0,0x808080,0x800000,0x800080,0x008000,0x008080]  + [0x000000 for i in range(17)] + [0xFFFFFF]
palette_array8bit = []
for idx,rgb in enumerate(palette8bit):
    s_rgb = "%06x" % rgb
    r = int(s_rgb[:2],16)
    g = int(s_rgb[2:4],16)
    b = int(s_rgb[4:],16)
    palette_array8bit.extend( (r, g, b) )

def _bzdump_list(self, x=256, b=8, lfilter=None, split=False, title=None, command=None):
    """bzdump() to each packets. (PIL required)

    @param x: width of an image
    @type x: int
    @param b: bit to eat per color
    @type b: int
    @param split: if True then split self each by RED line.
    @type split: bool
    @param title: Title of window.
    @type title: str
    @param command: default="display"
    @type command: str
    @param lfilter: a function that decides whether a packet must be displayed
    @type lfilter: lambda
    """
    s = ""
    for i in range(len(self.res)):
        p = self._elt2pkt(self.res[i])
        if lfilter is not None and not lfilter(p):
            continue
        p_s = str(p)
        s += p_s
        if split:
            if len(p_s) % x:
                s += x*"\x05"# RED LINE
            else:
                s += (len(p_s) % x)*"\x00" # append new BLACK line
                s += x*"\x05"# RED LINE
    return bzdump(s, x=x, b=b, title=title, command=command)

PacketList.bzdump = _bzdump_list

@conf.commands.register
def bzdump(s, x=256, b=8, title=None, command=None):
    """BZEditor bitmap drawing. (PIL required)
    @see https://sites.google.com/site/bzeditortama/

    @param x: width of an image
    @type x: int
    @param b: bit to eat per color
    @type b: int
    @param title: Title of window.
    @type title: str
    @param command: default="display"
    @type command: str
    """
    s_size = len(s)
    y = s_size / x
    if s_size % x:
        y += 1
    if b == 8:
        img = Image.new('P', (x, y))
    elif b == 24:
        img = Image.new('RGB', (x,y))
    elif b == 32:
        img = Image.new('RGBA', (x,y))
    else:
        raise TypeError("only 8 or 24 or 32 bit is allowed")
    if b == 8:#8bit = 1byte
        img.putdata(s)
        img.putpalette(palette_array8bit)
    elif b== 24:#24bit = 3bytes
        #TODO: pick last 2 or 1 bytes
        img.putdata([ tuple(map(ord,c3)) for c3 in split_str(s,3) if len(c3) == 3])
    elif b== 32:#32bit = 4bytes
        #TODO: pick last 3 or 2 or 1 bytes
        img.putdata([ tuple(map(ord,c4)) for c4 in split_str(s,4) if len(c4) == 4])
    if title is not None and command is not None:
        img.show(title,command)
    elif title is not None:
        img.show(title)
    elif command is not None:
        img.show(command)
    else:
        img.show(title="BZDUMP - %dBit Mode Bitmap" % b)
