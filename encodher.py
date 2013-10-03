#!/usr/bin/env python
"""
encoDHer - a python package for symmetric encryption of email
using the Diffie-Hellman shared secret key protocol.

Copyright (C) 2013 by David R. Andersen

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

For more information, see https://github.com/rxcomm/encoDHer
"""


import os
import sys
import hsub
import gnupg
import getpass
import dhutils
import re
import time
import string
import random
import StringIO
import rfc822
import nntplib
from constants import *

gpg = gnupg.GPG(gnupghome=HOME, gpgbinary=GPGBINARY, keyring=KEYRING,
                secret_keyring=SECRET_KEYRING, options='--throw-keyids')
gpg.encoding = 'utf-8'

try:
    opt = sys.argv[1]
except (IndexError):
    print 'Options:'
    print ' --init, -i: initialize keys.db database'
    print ' --import, -m: import signed public key'
    print ' --mutate-key, -a: mutate DH secret key for PFS'
    print ' --sign-pub, -s: sign your own public key'
    print ' --change-toemail, -t: change toEmail on key'
    print ' --change-fromemail, -f: change fromEmail on key'
    print ' --change-pubkey, -p: change public key for fromEmail -> toEmail'
    print ' --encode-email, -e: symmetrically encode a file for fromEmail -> toEmail'
    print ' --decode-email, -d: symmetrically decode a file for fromEmail -> toEmail'
    print ' --list-keys, -l: list all keys in database'
    print ' --gen-secret, -c: generate shared secret for fromEmail -> toEmail'
    print ' --gen-key, -n: generate a new key for fromEmail -> toEmail'
    print ' --get-key, -g: get key for fromEmail -> toEmail from database'
    print ' --fetch-aam, -h: fetch messages from alt.anonymous.messages newsgroup'
    print ' --clone-key, -y: clone key from one route to another'
    sys.exit(0)

def init():

    dhutils.initDB()

def importKey():

    try:
        file = sys.argv[2]
    except (IndexError):
        print 'You need to supply a source key file!'
        print 'Ex: '+sys.argv[0]+' --import <key file>'
        sys.exit(1)

    try:
        with open('keys.db'): pass
    except IOError:
        print 'No keys database (keys.db)'
        print 'initialize the database with '+sys.argv[0]+' --init'
        sys.exit(1)

    print 'Importing new DH public key to database'

    with open (file, "r") as f:
        signed_data=f.read()

    verified = gpg.verify(str(signed_data))
    if verified.username is not None:
        print('Verified signed by: %s' % verified.username)
        print('at trust level: %s' % verified.trust_text)
    else:
        print 'Signature not valid'
        sys.exit(0)

    data = signed_data.split('\n')
    pubkey = ''
    for line in data:
        if len(line) == 50:
            pubkey += line
    while pubkey[:1] == '0':
        pubkey = pubkey[1:]

    toEmail = verified.username.split('<')[1].split('>')[0]
    print 'To Email is: %s' % toEmail.lower()
    fromEmail = raw_input('Enter From Email: ')

    keys = dhutils.getKeys(fromEmail.lower(),toEmail.lower())

    if not keys:
        print 'key doesn\'t exist for the '+fromEmail+' -> '+toEmail+' route'
        print 'create new key?'
        ans = raw_input('y/N: ')
        if ans == 'y':
            dhutils.makeKeys()
            dhutils.insertKeys(fromEmail.lower(), toEmail.lower(), pubkey.lower())
    else:
        print 'key exists for the '+fromEmail.lower()+' -> '+toEmail.lower()+' route'
        print 'change key?'
        ans = raw_input('y/N: ')
        if ans == 'y':
            dhutils.changePubKey(fromEmail.lower(),toEmail.lower(),pubkey.lower())


def sign_pub():

    try:
        fromEmail = sys.argv[2]
        toEmail = sys.argv[3]

    except (IndexError):
        print 'You need to supply source and target email addresses!'
        print 'Ex: '+sys.argv[0]+' --sign-pub <fromEmail> <toEmail>'
        sys.exit(1)

    try:
        with open('keys.db'): pass
    except IOError:
        print 'No keys database (keys.db)'
        print 'initialize the database with '+sys.argv[0]+' --init'
        sys.exit(1)

    privkey, mypubkey, otherpubkey = dhutils.getKeys(fromEmail,toEmail)
    while len(mypubkey) < 37*50:
        mypubkey = '0'+mypubkey
    brokenkey = [mypubkey[i:i+50] for i in range(0, len(mypubkey), 50)]
    new_mypubkey = ''
    for line in brokenkey:
        new_mypubkey += line+'\n'

    passphrase = getpass.getpass('Signing key ('+fromEmail+') password: ')
    signed_data = gpg.sign('DH Public Key:\n'+new_mypubkey+'\n', passphrase=passphrase, keyid=fromEmail)
    print ''
    print str(signed_data)

    verified = gpg.verify(str(signed_data))
    if verified.username is not None:
        print('Verified signed by: %s' % verified.username)
        print('at trust level: %s' % verified.trust_text)
    else:
        print 'Sigature not verified'

def change_toEmail():
    try:
        fromEmail = sys.argv[2]
        oldToEmail = sys.argv[3]
        newToEmail = sys.argv[4]

    except (IndexError):
        print 'You need to supply fromEmail, oldToEmail, and newToEmail addresses'
        print 'Ex: '+sys.argv[0]+' --change-toemail <fromEmail> <oldToEmail> <newToEmail>'
        sys.exit(1)

    try:
        with open('keys.db'): pass
    except IOError:
        print 'No keys database (keys.db)'
        print 'initialize the database with '+sys.argv[0]+' --init'
        sys.exit(1)

    keys = dhutils.changeToEmail(fromEmail,oldToEmail,newToEmail)


def change_fromEmail():
    try:
        oldFromEmail = sys.argv[2]
        newFromEmail = sys.argv[3]
        toEmail = sys.argv[4]

    except (IndexError):
        print 'You need to supply oldFromEmail, newFromEmail, and toEmail addresses'
        print 'Ex: '+sys.argv[0]+' --change-fromemail <oldFromEmail> <newFromEmail> <toEmail>'
        sys.exit(1)

    try:
        with open('keys.db'): pass
    except IOError:
        print 'No keys database (keys.db)'
        print 'initialize the database with '+sys.argv[0]+' --init'
        sys.exit(1)

    keys = dhutils.changeFromEmail(oldFromEmail,newFromEmail,toEmail)

def change_pub():
    try:
        fromEmail = sys.argv[2]
        toEmail = sys.argv[3]
        pubkey = sys.argv[4]

    except (IndexError):
        print 'You need to supply fromEmail, toEmail, and public key!'
        print 'Ex: '+sys.argv[0]+' --change-pub <fromEmail> <toEmail> <pub-key>'
        sys.exit(1)

    try:
        with open('keys.db'): pass
    except IOError:
        print 'No keys database (keys.db)'
        print 'initialize the database with '+sys.argv[0]+' --init'
        sys.exit(1)

    keys = dhutils.changePubKey(fromEmail,toEmail,pubkey)

def hs():
    try:
        file_name = sys.argv[2]
        fromEmail = sys.argv[3]
        toEmail = sys.argv[4]
    except (IndexError):
        print 'You need to supply a target file to be encrypted, fromEmail, and toEmail!'
        print 'Ex: '+sys.argv[0]+' --encode-email <file> <fromEmail> <toEMail>'
        sys.exit(1)

    try:
        with open('keys.db'): pass
    except IOError:
        print 'No keys database (keys.db)'
        print 'initialize the database with '+sys.argv[0]+' --init'
        sys.exit(1)

    ans = raw_input('Do you want to send this message anonymously? (y/N)')
    if ans == 'y':
        sendAnon = True
    else:
        sendAnon = False

    passphrase = dhutils.genSharedSecret(fromEmail, toEmail)

    with open(file_name, "rb") as f:
        msg = gpg.encrypt_file(f, recipients=None, symmetric='AES256',
              always_trust=True, passphrase=passphrase)
        if sendAnon:
            iv = hsub.cryptorandom()
            hsubject = hsub.hash(passphrase[:16]) # first 64 bits to calc hsub

            # A note here about using part of the passphrase as the hsub password.
            # We use 64 bits (16 ascii bytes hex encoded = 8 bytes binary entropy)
            # for the hsub passphrase.  Assuming those 64 bits are completely
            # compromised (unlikekly, as it would require a rainbow table with
            # 3.4 x 10^38 entries) that leaves us with 192 bits of aes key entropy.
            # Still plenty strong.

    with open(file_name+'.asc', "w") as f:

        if sendAnon:
            f.write('To: mail2news@dizum.com,mail2news@m2n.mixmin.net\n')
            f.write('Subject: %s\n' % hsubject)
            f.write('Newsgroups: alt.anonymous.messages\n')
            f.write('X-No-Archive: Yes\n')
            f.write('\n')
        f.write(re.sub('\nV.*$', '', str(msg), count=1, flags=re.MULTILINE))

    print 'Passphrase: %s' % passphrase


def hsd():
    try:
        file_name = sys.argv[2]
        fromEmail = sys.argv[3]
        toEmail = sys.argv[4]
    except (IndexError):
        print 'You need to supply a target file to be decrypted, fromEmail, and toEmail!'
        print 'Ex: '+sys.argv[0]+' --decode-email <file> <fromEmail> <toEmail>'
        sys.exit(1)

    try:
        with open('keys.db'): pass
    except IOError:
        print 'No keys database (keys.db)'
        print 'initialize the database with '+sys.argv[0]+' --init'
        sys.exit(1)

    base, ext = os.path.splitext(file_name)
    with open(file_name, "r") as f:
        passphrase = dhutils.genSharedSecret(toEmail, fromEmail)
        msg = gpg.decrypt_file(f, passphrase=passphrase, always_trust=True)
        if not msg:
            print 'Bad shared secret!'
            sys.exit(1)
        print '\n'+str(msg)


def list_keys():
    try:
        with open('keys.db'): pass
    except IOError:
        print 'No keys database (keys.db)'
        print 'initialize the database with '+sys.argv[0]+' --init'
        sys.exit(1)

    print 'Listing of all keys in database:'
    dhutils.listKeys()

def secret():
    try:
        fromEmail = sys.argv[2]
        toEmail = sys.argv[3]
    except (IndexError):
        print 'You need to supply a fromEmail, and toEmail!'
        print 'Ex: '+sys.argv[0]+' --gen-secret <fromEmail> <toEmail>'
        sys.exit(1)

    try:
        with open('keys.db'): pass
    except IOError:
        print 'No keys database (keys.db)'
        print 'initialize the database with '+sys.argv[0]+' --init'
        sys.exit(1)

    sharedSecret = dhutils.genSharedSecret(fromEmail,toEmail)
    print 'Secret: ',sharedSecret

def gen():
    try:
        fromEmail = sys.argv[2]
        toEmail = sys.argv[3]
    except (IndexError):
        print 'You need to supply a fromEmail, and toEmail!'
        print 'Ex: '+sys.argv[0]+' --gen-key <fromEmail> <toEmail>'
        sys.exit(1)

    try:
        with open('keys.db'): pass
    except IOError:
        print 'No keys database (keys.db)'
        print 'initialize the database with '+sys.argv[0]+' --init'
        sys.exit(1)

    dhutils.makeKeys()
    dhutils.insertKeys(fromEmail,toEmail,1)


def get():
    try:
        fromEmail = sys.argv[2]
        toEmail = sys.argv[3]
    except (IndexError):
        print 'You need to supply a fromEmail, and toEmail!'
        print 'Ex: '+sys.argv[0]+' --get-key <fromEmail> <toEmail>'
        sys.exit(1)

    try:
        with open('keys.db'): pass
    except IOError:
        print 'No keys database (keys.db)'
        print 'initialize the database with '+sys.argv[0]+' --init'
        sys.exit(1)

    privkey, mypubkey, otherpubkey = dhutils.getKeys(fromEmail,toEmail)
    print fromEmail+' Public Key: ', mypubkey
    print toEmail+' Public Key: ', otherpubkey

def delete():
    try:
        fromEmail = sys.argv[2]
        toEmail = sys.argv[3]
    except (IndexError):
        print 'You need to supply a fromEmail, and toEmail!'
        print 'Ex: '+sys.argv[0]+' --delete-key <fromEmail> <toEmail>'
        sys.exit(1)

    try:
        with open('keys.db'): pass
    except IOError:
        print 'No keys database (keys.db)'
        print 'initialize the database with '+sys.argv[0]+' --init'
        sys.exit(1)

    dhutils.deleteKey(fromEmail,toEmail)

def mutate():
    try:
        fromEmail = sys.argv[2]
        toEmail = sys.argv[3]
    except (IndexError):
        print 'You need to supply a fromEmail, and toEmail!'
        print 'Ex: '+sys.argv[0]+' --mutate-key <fromEmail> <toEmail>'
        sys.exit(1)

    try:
        with open('keys.db'): pass
    except IOError:
        print 'No keys database (keys.db)'
        print 'initialize the database with '+sys.argv[0]+' --init'
        sys.exit(1)

    oldpassphrase = dhutils.genSharedSecret(fromEmail,toEmail)
    dhutils.mutateKey(fromEmail,toEmail)

    privkey, mypubkey, otherpubkey = dhutils.getKeys(fromEmail,toEmail)
    while len(mypubkey) < 37*50:
        mypubkey = '0'+mypubkey
    brokenkey = [mypubkey[i:i+50] for i in range(0, len(mypubkey), 50)]
    new_mypubkey = ''
    for line in brokenkey:
        new_mypubkey += line+'\n'

    passphrase = getpass.getpass('Signing key ('+fromEmail+') password: ')
    signed_data = gpg.sign('DH Public Key:\n'+new_mypubkey+'\n', passphrase=passphrase, keyid=fromEmail)
    print ''
    print str(signed_data)

    ans = raw_input('Do you want to send this key anonymously? (y/N)')
    if ans == 'y':
        sendAnon = True
    else:
        sendAnon = False

    msg = gpg.encrypt(str(signed_data), recipients=None, symmetric='AES256',
          always_trust=True, passphrase=oldpassphrase)
    if sendAnon:
        iv = hsub.cryptorandom()
        hsubject = hsub.hash(oldpassphrase)

    with open('mutatedkey.asc', "w") as f:

        if sendAnon:
            f.write('To: mail2news@dizum.com,mail2news@m2n.mixmin.net\n')
            f.write('Subject: %s\n' % hsubject)
            f.write('Newsgroups: alt.anonymous.messages\n')
            f.write('X-No-Archive: Yes\n')
            f.write('\n')
        f.write(re.sub('\nV.*$', '', str(msg), count=1, flags=re.MULTILINE))
        print 'New key encrypted with old DH shared secret is in "mutatedkey.asc"'
        print 'Get unencrypted, signed copy of new key with '+sys.argv[0]+' --sign-pub '+fromEmail+' '+toEmail

def aam():
    GROUP  = "alt.anonymous.messages"

    timeStamp = dhutils.getNewsTimestamp()
    YYMMDD = time.strftime('%y%m%d', time.gmtime(timeStamp))
    HHMMSS = time.strftime('%H%M%S', time.gmtime(timeStamp))

    passphrases = dhutils.getListOfKeys()

    # connect to server
    server = nntplib.NNTP(NEWSSERVER,NEWSPORT)

    server.newnews(GROUP, YYMMDD, HHMMSS, '.newnews')

    with open ('.newnews', "r") as f:
        ids=f.read().splitlines()

        for msg_id in ids:
            try:
                resp, id, message_id, text = server.article(msg_id)
            except (nntplib.error_temp, nntplib.error_perm):
                pass # no such message (maybe it was deleted?)
            text = string.join(text, "\n")
            file = StringIO.StringIO(text)

            message = rfc822.Message(file)

            for passphrase in passphrases:
                for label, item in message.items():
                    if label == 'subject':
                        match = hsub.check(passphrase[2][:16],item)

                #if match: print message.fp.read()
                if match:

                    print '\nMail for: '+passphrase[0]+' from '+passphrase[1]
                    msg = gpg.decrypt(message.fp.read(), passphrase=passphrase[2],
                          always_trust=True)
                    if not msg:
                        print 'Bad shared secret!'
                        sys.exit(1)
                    print '\n'+str(msg)
    print 'End of messages.'

def clone():
    try:
        fromEmail = sys.argv[2]
        toEmail = sys.argv[3]
        newFromEmail = sys.argv[4]
        newToEmail = sys.argv[5]
    except (IndexError):
        print 'You need to supply a fromEmail, and toEmail!'
        print 'Ex: '+sys.argv[0]+' --clone-key <oldFromEmail> <oldToEmail> <newFromEmail> <newToEmail>'
        sys.exit(1)

    try:
        with open('keys.db'): pass
    except IOError:
        print 'No keys database (keys.db)'
        print 'initialize the database with '+sys.argv[0]+' --init'
        sys.exit(1)

    dhutils.cloneKey(fromEmail,toEmail,newFromEmail,newToEmail)

def errhandler():
    print 'Invalid option, try again!'
    print 'Execute '+sys.argv[0]+' to get a list of options.'
    sys.exit(1)

options = { '--init'   : init,
  '-i'   : init,
  '--import' : importKey,
  '-m' : importKey,
  '--sign-pub' : sign_pub,
  '-s' : sign_pub,
  '--change-toemail' : change_toEmail,
  '-t' : change_toEmail,
  '--change-fromemail' : change_fromEmail,
  '-f' : change_fromEmail,
  '--change-pubkey' : change_pub,
  '-p' : change_pub,
  '--encode-email' : hs,
  '-e' : hs,
  '--decode-email' : hsd,
  '-d' : hsd,
  '--list-keys' : list_keys,
  '-l' : list_keys,
  '--gen-secret' : secret,
  '-c' : secret,
  '--gen-key' : gen,
  '-n' : gen,
  '--get-key' : get,
  '-g' : get,
  '--delete-key' : delete,
  '-x' : delete,
  '--mutate-key' : mutate,
  '-a' : mutate,
  '--fetch-aam' : aam,
  '-h' : aam,
  '--clone-key' : clone,
  '-y' : clone
}

options.get(sys.argv[1],errhandler)()
