import subprocess
from distutils.core import setup

#setup(name='encoDHer',
#      version='0.1',
#      description='symmetric email utility for python',
#      author='David R. Andersen',
#      url='https://github.com/rxcomm/encoDHer',
#     py_modules=['encodher','dhutils','dh','constants','hsub'],
#     )

subprocess.call('./make_exec.sh')
