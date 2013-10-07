#!/usr/bin/env python

import os

user_path = os.path.expanduser('~')
config_path = user_path+'/.config/encoDHer'

if not os.path.exists(config_path):
    os.makedirs(config_path)

# working directory
HOME = config_path # should be ~/.config/encoDHer for most installs

# GPG public keyring
KEYRING = [config_path+'/pubring.gpg', user_path+'/.gnupg/pubring.gpg']

# GPG secret keyring
SECRET_KEYRING = [config_path+'/secring.gpg', user_path+'/.gnupg/secring.gpg']

# GPG binary
#GPGBINARY = '/usr/bin/gpg'
GPGBINARY = '/usr/bin/gpg2'

# newsserver address
NEWSSERVER = "localhost"

# newsserver port
NEWSPORT = 119

# location of keys database
KEYS_DB = config_path+'/keys.db'
