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

import dh
import sqlite3
import sys
import os
import time
import hashlib
import getpass
from binascii import hexlify
from constants import *

def makeKeys():
    """
    Create a DH keyset
    """

    a = dh.DiffieHellman()
    privkey = a.privateKey
    pubkey = a.publicKey
    return str(privkey), str(pubkey)

def initDB(gpg,dbpassphrase):
    """
    Initialize the database with the keys table format and
    a timestamp marking the beginning of time to search a.a.m
    """

    timeStamp = time.time()
    print timeStamp

    try:
        with open(KEYS_DB): pass
        db = openDB(KEYS_DB,gpg,dbpassphrase)
    except IOError:
        db = sqlite3.connect(':memory:')

    with db:

        cur = db.cursor()
        cur.execute('CREATE TABLE IF NOT EXISTS keys (FromEmail TEXT, ToEmail TEXT, SecretKey TEXT, PublicKey TEXT, OtherPublicKey TEXT, TimeStamp FLOAT)')
        cur.execute('CREATE TABLE IF NOT EXISTS news (Id INTEGER PRIMARY KEY, LastReadTime FLOAT)')
        cur.execute('INSERT OR REPLACE INTO news (Id, LastReadTime) VALUES(?,?)', (1,timeStamp))
    closeDB(db, KEYS_DB, gpg,dbpassphrase)
    os.chmod(KEYS_DB,0600)

def rollback(days,gpg,dbpassphrase):
    """
    Roll back the database news timestamp.
    The timestamp marks the beginning of time to search a.a.m
    """

    timeStamp = time.time() - int(days)*86400
    print timeStamp
    db = openDB(KEYS_DB,gpg,dbpassphrase)

    with db:

        cur = db.cursor()
        cur.execute('UPDATE news SET LastReadTime = ? WHERE Id = ?', (timeStamp,1))
    closeDB(db, KEYS_DB, gpg,dbpassphrase)

def insertKeys(fromEmail,toEmail,otherpubkey,gpg,dbpassphrase):
    """
    Create a new keyset for the fromEmail -> toEmail route
    """

    db = openDB(KEYS_DB, gpg,dbpassphrase)
    otherpubkey = str(otherpubkey)

    with db:

        timeStamp = time.time()
        privkey, mypubkey = makeKeys()
        cur = db.cursor()
        cur.execute('CREATE TABLE IF NOT EXISTS keys (FromEmail TEXT, ToEmail TEXT, SecretKey TEXT, PublicKey TEXT, OtherPublicKey TEXT, TimeStamp INT)')
        cur.execute('INSERT INTO keys VALUES(?,?,?,?,?,?)', (fromEmail,toEmail,privkey,mypubkey,otherpubkey,timeStamp))

        cur.execute("SELECT * FROM keys")
        rows = cur.fetchall()
        print 'You have %d total routes' % len(rows)
    closeDB(db, KEYS_DB, gpg,dbpassphrase)

def getKeys(fromEmail,toEmail,gpg,dbpassphrase):
    """
    Get the key for the fromEmail -> toEmail route
    return privkey, mypubkey, otherpubkey
    """

    db = openDB(KEYS_DB, gpg,dbpassphrase)

    with db:

        cur = db.cursor()
        cur.execute("SELECT * FROM keys")
        rows = cur.fetchall()
        for row in rows:
            if row[0] == fromEmail and row[1] == toEmail:
                return row[2], row[3], row[4]

def listKeys(gpg,dbpassphrase):
    """
    List routes for all keys in database
    """

    db = openDB(KEYS_DB, gpg,dbpassphrase)

    with db:

        cur = db.cursor()
        cur.execute("SELECT * FROM keys")
        rows = cur.fetchall()
        for row in rows:
            print row[0]+' -> '+row[1]
        print 'You have %d total routes' % len(rows)

def cloneKey(fromEmail,toEmail,newFromEmail,newToEmail,gpg,dbpassphrase):
   """
   Clone key from route fromEmail -> toEmail to new route newFromEmail -> newToEmail
   """

   db = openDB(KEYS_DB, gpg,dbpassphrase)

   with db:

       changed = False
       cur = db.cursor()
       cur.execute("SELECT * FROM keys")
       rows = cur.fetchall()
       for row in rows:
           if row[0] == fromEmail and row[1] == toEmail:
               changed = True
               cur.execute('INSERT INTO keys VALUES(?,?,?,?,?,?)', (newFromEmail,newToEmail,row[2],row[3],row[4],row[5]))
       if not changed: print 'Matching key not found, nothing changed.'
   closeDB(db, KEYS_DB, gpg,dbpassphrase)

def changePubKey(fromEmail,toEmail,pubkey,gpg,dbpassphrase):
    """
    Change the otherpubkey for the fromEmail -> toEmail route
    """

    db = openDB(KEYS_DB, gpg,dbpassphrase)

    with db:

        changed = False
        cur = db.cursor()
        cur.execute("SELECT * FROM keys")
        rows = cur.fetchall()
        for row in rows:
            if row[0] == fromEmail and row[1] == toEmail:
                changed = True
                cur.execute('UPDATE keys SET OtherPublicKey = ? WHERE FromEmail = ? AND ToEmail = ?', (pubkey,row[0],row[1]))
        if not changed: print 'Matching key not found, nothing changed.'
    closeDB(db, KEYS_DB, gpg,dbpassphrase)

def changeToEmail(fromEmail,oldToEmail,newToEmail,gpg,dbpassphrase):
    """
    Change the toEmail address on the fromEmail -> oldToEmail route
    """

    db = openDB(KEYS_DB, gpg,dbpassphrase)

    with db:

        changed = False
        cur = db.cursor()
        cur.execute("SELECT * FROM keys")
        rows = cur.fetchall()
        for row in rows:
            if row[0] == fromEmail and row[1] == oldToEmail:
                changed = True
                cur.execute('UPDATE keys SET ToEmail = ? WHERE FromEmail = ? AND ToEmail = ?', (newToEmail,row[0],row[1]))
        if not changed: print 'Matching key not found, nothing changed.'
    closeDB(db, KEYS_DB, gpg,dbpassphrase)

def changeFromEmail(oldFromEmail,newFromEmail,toEmail,gpg,dbpassphrase):
    """
    Change the fromEmail address on the oldFromEmail -> toEmail route
    """

    db = openDB(KEYS_DB, gpg,dbpassphrase)

    with db:

        changed = False
        cur = db.cursor()
        cur.execute("SELECT * FROM keys")
        rows = cur.fetchall()
        for row in rows:
            if row[0] == oldFromEmail and row[1] == toEmail:
                changed = True
                cur.execute('UPDATE keys SET FromEmail = ? WHERE FromEmail = ? AND ToEmail = ?', (newFromEmail,row[0],row[1]))
        if not changed: print 'Matching key not found, nothing changed.'
    closeDB(db, KEYS_DB, gpg,dbpassphrase)

def deleteKey(fromEmail,toEmail,gpg,dbpassphrase):
    """
    Delete the fromEmail -> toEmail key from the database
    """

    db = openDB(KEYS_DB, gpg,dbpassphrase)

    with db:

        cur = db.cursor()
        cur.execute("SELECT * FROM keys")
        rows = cur.fetchall()
        for row in rows:
            if row[0] == fromEmail and row[1] == toEmail:
                cur.execute('DELETE FROM keys WHERE FromEmail = ? AND ToEmail = ?', (fromEmail,toEmail))
    closeDB(db, KEYS_DB, gpg,dbpassphrase)

def genSharedSecret(fromEmail,toEmail,gpg,dbpassphrase):
    """
    Generate the shared secret for the fromEmail -> toEmail route
    """

    try:
        a = dh.DiffieHellman()
        privkey, mypubkey, otherpubkey = getKeys(fromEmail,toEmail,gpg,dbpassphrase)
        a.privateKey = long(privkey)
        sharedSecret = a.genSecret(long(privkey),long(otherpubkey))
        s = hashlib.sha256()
        s.update(str(sharedSecret))
        return hexlify(s.digest())
    except Exception:
        print 'Invalid public key: %s -> %s' % (fromEmail, toEmail)

def mutateKey(fromEmail,toEmail,gpg,dbpassphrase):
    """
    Change the privkey, mypubkey pair on the fromEmail -> toEmail route
    without modifying the otherpubkey.  Also, create a mutatekey.asc file
    containing the new mypubkey encrypted with the old shared secret.
    This file can be securely transmitted to the receiver for decryption
    and importation to complete the key swap process. This makes the
    old shared secret disappear completely once the receiver has imported
    the new key. (ephemeral DH - perfect forward secrecy)
    """

    db = openDB(KEYS_DB, gpg,dbpassphrase)

    with db:

        changed = False
        timeStamp = time.time()
        privkey, mypubkey = makeKeys()
        cur = db.cursor()
        cur.execute("SELECT * FROM keys")
        rows = cur.fetchall()
        for row in rows:
            if row[0] == fromEmail and row[1] == toEmail:
                changed = True
                cur.execute('UPDATE keys SET SecretKey = ? WHERE FromEmail = ? AND ToEmail = ?', (privkey,fromEmail,toEmail))
                cur.execute('UPDATE keys SET PublicKey = ? WHERE FromEmail = ? AND ToEmail = ?', (mypubkey,fromEmail,toEmail))
        if not changed: print 'Matching key not found, nothing changed.'
    closeDB(db, KEYS_DB, gpg,dbpassphrase)

def getNewsTimestamp(gpg,dbpassphrase):
    """
    Get the old timestamp for reading messages from a.a.m, and replace
    the old timestamp with a new one for next time
    """

    curTimeStamp = time.time()
    db = openDB(KEYS_DB, gpg,dbpassphrase)

    with db:

        cur = db.cursor()
        cur.execute("SELECT * FROM news")
        rows = cur.fetchall()
        for row in rows:
            if row[0] == 1: timeStamp = int(row[1])-1
            cur.execute('UPDATE news SET LastReadTime = ? WHERE Id = 1', (curTimeStamp,))
        return timeStamp
    closeDB(db, KEYS_DB, gpg,dbpassphrase)

def getListOfKeys(gpg,dbpassphrase):
    """
    Get the route and shared secret for all keys in the database.  This
    will be used to query a.a.m for any messages associated with our keys.
    """

    db = openDB(KEYS_DB, gpg,dbpassphrase)
    listOfKeys = []

    with db:
        cur = db.cursor()
        cur.execute("SELECT * FROM keys")
        rows = cur.fetchall()
        for row in rows:
            sSecret = genSharedSecret(row[0],row[1],gpg,dbpassphrase)
            if sSecret:
                listOfKeys.append((row[0],row[1],sSecret))
        return listOfKeys

def openDB(keys_db,gpg,dbpassphrase):

    db = sqlite3.connect(':memory:')

    with open(keys_db, 'rb') as f:
        sql = gpg.decrypt_file(f, passphrase=dbpassphrase)
        if not sql:
            print 'Bad passphrase!'
            sys.exit(1)
        db.cursor().executescript(str(sql))
    return db

def closeDB(db, keys_db,gpg,dbpassphrase):

    passphrase1='1'
    passphrase2='2'
    while passphrase1 != passphrase2:
        passphrase1 = getpass.getpass('Passphrase to ENCRYPT keys.db: ')
        passphrase2 = getpass.getpass('Retype: ')
        if passphrase1 != passphrase2:
            print 'Passphrase did not match.'
    sql = ''
    for item in db.iterdump():
        sql = sql+item+'\n'
    crypt_sql = gpg.encrypt(sql, recipients=None, symmetric='AES256',
                            always_trust=True, passphrase=passphrase1)

    with open(keys_db, 'wb') as f:
        f.write(str(crypt_sql))

if __name__=="__main__":
    """
    Run an example key insertion
    """
    makeKeys()
    insertKeys(sys.argv[1], sys.argv[2], sys.argv[3])
    sharedSecret = genSharedSecret(sys.argv[1], sys.argv[2])
    print sharedSecret
    print len(sharedSecret)

