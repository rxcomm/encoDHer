#!/bin/bash

[ -a encodher ] && rm encodher
zip -q -r encodher.zip *.pyc __main__.py
echo '#!/usr/bin/env python' | cat - encodher.zip > encodher
chmod +x encodher
user=$(id -u -n)
[ $SUDO_USER ] && user=$SUDO_USER || user=`whoami`
chown $user:$user encodher
rm encodher.zip
