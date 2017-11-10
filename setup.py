#! /usr/bin/env python3

"""
Distutils setup file for Scapy.
"""


from distutils import archive_util
from distutils import sysconfig
from distutils.core import setup
from distutils.command.sdist import sdist
import os


EZIP_HEADER="""#! /bin/sh
PYTHONPATH=$0/%s exec python3 -m scapy.__init__
"""

def make_ezipfile(base_name, base_dir, verbose=0, dry_run=0, **kwargs):
    fname = archive_util.make_zipfile(base_name, base_dir, verbose, dry_run)
    ofname = fname+".old"
    os.rename(fname,ofname)
    of=open(ofname)
    f=open(fname,"w")
    f.write(EZIP_HEADER % base_dir)
    while True:
        data = of.read(8192)
        if not data:
            break
        f.write(data)
    f.close()
    os.system("zip -A '%s'" % fname)
    of.close()
    os.unlink(ofname)
    os.fchmod(fname,0o755)
    return fname



archive_util.ARCHIVE_FORMATS["ezip"] = (make_ezipfile,[],'Executable ZIP file')

SCRIPTS = ['bin/scapy','bin/UTscapy']
# On Windows we also need additional batch files to run the above scripts 
if os.name == "nt":
  SCRIPTS += ['bin/scapy.bat','bin/UTscapy.bat']

setup(
    name = 'scapy-python3',
    version = '0.22',
    packages=['scapy','scapy/arch', 'scapy/arch/windows', 'scapy/layers','scapy/asn1','scapy/tools','scapy/modules', 'scapy/crypto', 'scapy/contrib'],
    scripts = SCRIPTS,
    data_files = [('share/man/man1', ["doc/scapy.1.gz"])],

    # Metadata
    maintainer = 'Eriks Dobelis',
    maintainer_email = 'phaethon@users.noreply.github.com',
    description = 'Packet crafting/sending/sniffing, PCAP processing tool, based on scapy with python3 compatibility',
    license = 'GPLv2',
    url = 'https://github.com/phaethon/scapy',
    keywords = 'network security monitoring packet pcap analytics visualization',
    classifiers = [
      'Development Status :: 5 - Production/Stable',
      'Environment :: Console',
      'Operating System :: POSIX',
      'Operating System :: Microsoft :: Windows',
      'Programming Language :: Python :: 3',
      'Programming Language :: Python :: 3 :: Only',
      'Programming Language :: Python :: 3.4',
      'Programming Language :: Python :: 3.5',
      'Programming Language :: Python :: 3.6',
    ]
)
