#! /usr/bin/env python3

"""
Distutils setup file for kamene.
"""


from distutils import archive_util
from distutils import sysconfig
from distutils.core import setup
from distutils.command.sdist import sdist
import os


EZIP_HEADER="""#! /bin/sh
PYTHONPATH=$0/%s exec python3 -m kamene.__init__
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

SCRIPTS = ['bin/kamene','bin/UTkamene']
# On Windows we also need additional batch files to run the above scripts 
if os.name == "nt":
  SCRIPTS += ['bin/kamene.bat','bin/UTkamene.bat']

setup(
    name = 'kamene',
    version = '0.32',
    packages=['kamene','kamene/arch', 'kamene/arch/windows', 'kamene/layers','kamene/asn1','kamene/tools','kamene/modules', 'kamene/crypto', 'kamene/contrib'],
    scripts = SCRIPTS,
    data_files = [('share/man/man1', ["doc/kamene.1.gz"])],

    # Metadata
    maintainer = 'Eriks Dobelis',
    maintainer_email = 'phaethon@users.noreply.github.com',
    description = 'Packet crafting/sending/sniffing, PCAP processing tool, originally forked from scapy',
    license = 'GPLv2',
    url = 'https://github.com/phaethon/kamene',
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
