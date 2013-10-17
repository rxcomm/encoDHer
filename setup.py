try:
    from setuptools import setup
except:
    from distutils.core import setup
import zipfile
import os
import pwd

setup(name='encoDHer',
      version='0.3',
      description='symmetric email encryption utility for python',
      author='David R. Andersen',
      url='https://github.com/rxcomm/encoDHer',
      py_modules=['encodher','dhutils','dh','constants','hsub'],
      install_requires=['python-gnupg >= 0.3.5'],
     )


with zipfile.ZipFile('encodher', 'w', zipfile.ZIP_DEFLATED) as z:
    z.write('__main__.py')
    z.write('encodher.py')
    z.write('dhutils.py')
    z.write('dh_m2crypto.py')
    z.write('dh_pydhe.py')
    z.write('dh_legacy.py')
    z.write('hsub.py')

with open('encodher', 'r+') as z:
    zipdata = z.read()
    z.seek(0)
    z.write('#!/usr/bin/env python\n'+zipdata)

user = os.getenv('SUDO_USER')
uid, gid = pwd.getpwnam(user)[2:4]
os.chown('encodher', uid, gid)
os.chmod('encodher',0755)
os.system('cp encodher /usr/local/bin/encodher')
os.system('cp dhparams.pem /usr/local/lib/dhparams.pem')
print 'encodher executable copied to /usr/local/bin/encodher'
