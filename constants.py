#!/usr/bin/env python

import os

user_path = os.path.expanduser('~')
config_path = user_path+'/.config/encoDHer'

if not os.path.exists(config_path):
    os.makedirs(config_path)

# working directory
HOME = config_path # should be ~/.config/encoDHer for most installs

# GPG public keyring
KEYRING = user_path+'/.gnupg/pubring.gpg' # use this for default GPG keyring
# KEYRING = 'pubring.gpg' # use this if you keep keyrings in ~/.config/encoDHer

# GPG secret keyring
SECRET_KEYRING = user_path+'/.gnupg/secring.gpg' # use this for default GPG keyring
# SECRET_KEYRING = 'secring.gpg' # use this if you keep keyrings in ~/.config/encoDHer

# GPG binary
#GPGBINARY = '/usr/bin/gpg'
GPGBINARY = '/usr/bin/gpg2'

# newsserver address
NEWSSERVER = "localhost"

# newsserver port
NEWSPORT = 119

# location of keys database
KEYS_DB = config_path+'/keys.db'
