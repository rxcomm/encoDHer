from distutils.core import setup
import zipfile
import os
import pwd

setup(name='encoDHer',
      version='0.1',
      description='symmetric email encryption utility for python',
      author='David R. Andersen',
      url='https://github.com/rxcomm/encoDHer',
     py_modules=['encodher','dhutils','dh','constants','hsub'],
     )


with zipfile.ZipFile('encodher', 'w', zipfile.ZIP_DEFLATED) as z:
    z.write('__main__.py')
    z.write('encodher.py')
    z.write('dhutils.py')
    z.write('dh.py')
    z.write('hsub.py')

with open('encodher', 'r+') as z:
    zipdata = z.read()
    z.seek(0)
    z.write('#!/usr/bin/env python\n'+zipdata)

user = os.getenv('SUDO_USER')
uid, gid = pwd.getpwnam(user)[2:4]
os.chown('encodher', uid, gid)
os.chmod('encodher',0755)
