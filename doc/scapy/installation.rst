.. highlight:: sh

*************************
Download and Installation
*************************

Overview
========

 0. Install *Python 3.x*.
 1. Download and install *Scapy*.
 2. (For non-Linux platforms): Install *libpcap and libdnet* and their Python wrappers.
 3. (Optional): Install *additional software* for special features.
 4. Run Scapy with root priviledges.
 
Each of these steps can be done in a different way dependent on your platform and on the version of Scapy you want to use. 

This document is for scapy3k. It requires python 3.x. See `original scapy homepage <http://www.secdev.org/projects/scapy/>` for Scapy v2.x or earlier.

.. note::

   In scapy3k and Scapy v2.x use ``from scapy.all import *`` instead of ``from scapy import *``.


Installing scapy3k
=====================

The following steps describe how to install (or update) Scapy itself.
Dependent on your platform, some additional libraries might have to be installed to make it actually work. 
So please also have a look at the platform specific chapters on how to install those requirements.

.. note::

   The following steps apply to Unix-like operating systems (Linux, BSD, Mac OS X). 
   Windows, currently is under development.

Make sure you have Python installed before you go on. Depending on your system you may have to use python3 and pip3 or python and pip for python version 3.x.

Latest release
--------------

Easiest way to install latest scapy3k package is using pip.

$ pip3 install scapy-python3
 
Current development version
----------------------------

Clone `GitHub repository <http://github.com/phaethon/scapy>`_ to a temporary directory and install it in the standard `distutils <http://docs.python.org/inst/inst.html>`_ way::

$ cd /tmp
$ git clone https://github.com/phaethon/scapy 
$ cd scapy
$ sudo python3 setup.py install

.. index::
   single: git, repository

If you always want the latest version with all new features and bugfixes, use Scapy's GitHub repository:

1. Install `git <https://git-scm.com/>`_ version control system. For example, on Debian/Ubuntu use::

      $ sudo apt-get install git

2. Check out a clone of Scapy's repository::
    
   $ git clone https://github.com/phaethon/scapy
    
3. Install Scapy in the standard distutils way:: 
    
   $ cd scapy
   $ sudo python3 setup.py install
    
Then you can always update to the latest version::

$ git pull
$ sudo python3 setup.py install
 

Optional software for special features
======================================

* WEP decryption. ``unwep()`` needs `PyCrypto <http://www.dlitz.net/software/pycrypto/>`_. Example using a `Weplap test file <http://weplab.sourceforge.net/caps/weplab-64bit-AA-managed.pcap>`_:

  .. code-block:: python

     >>> enc=rdpcap("weplab-64bit-AA-managed.pcap")
     >>> enc.show()
     >>> enc[0]
      >>> conf.wepkey=b"AA\x00\x00\x00"
      >>> dec=Dot11PacketList(enc).toEthernet()
      >>> dec.show()
      >>> dec[0]
 
Platform-specific instructions
==============================

Linux native
------------

Scapy can run natively on Linux, without libdnet and libpcap.

* Install `Python 3.x <http://www.python.org>`_.
* Install `tcpdump <http://www.tcpdump.org>`_ and make sure it is in the $PATH. (It's only used to compile BPF filters (``-ddd option``))
* Make sure your kernel has Packet sockets selected (``CONFIG_PACKET``)
* If your kernel is < 2.6, make sure that Socket filtering is selected ``CONFIG_FILTER``) 

Debian/Ubuntu
-------------

Just use the standard packages::

$ sudo apt-get install tcpdump python3-crypto ipython3


Mac OS X
--------

This section needs updating. In general installing python3, pip for python3, libpcap, libdnet, scapy3k using pip package scapy-python3 should do the job. Corrections are welcome...


Windows
-------

Scapy is primarily being developed for Unix-like systems and works best on those platforms. scapy3k has not yet been ported to Windows. Use at your own risk. 
 


