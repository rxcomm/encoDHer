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
import time
import sys
import hashlib
from binascii import hexlify

def makeKeys():
    """
    Create a DH keyset
    """

    a = dh.DiffieHellman()
    privkey = a.privateKey
    pubkey = a.publicKey
    del a
    return str(privkey), str(pubkey)

def initDB():
    """
    Initialize the database with the keys table format and
    a timestamp marking the beginning of time to search a.a.m
    """

    timeStamp = time.time()
    print timeStamp
    db = sqlite3.connect('keys.db')

    with db:

        cur = db.cursor()
        cur.execute('CREATE TABLE IF NOT EXISTS keys (FromEmail TEXT, ToEmail TEXT, SecretKey TEXT, PublicKey TEXT, OtherPublicKey TEXT, TimeStamp FLOAT)')
        cur.execute('CREATE TABLE IF NOT EXISTS news (Id INT, LastReadTime FLOAT)')
        cur.execute('INSERT INTO news (Id, LastReadTime) VALUES(?,?)', (1,timeStamp))

def insertKeys(fromEmail,toEmail,otherpubkey):
    """
    Create a new keyset for the fromEmail -> toEmail route
    """

    db = sqlite3.connect('keys.db')
    otherpubkey = str(otherpubkey)

    with db:

        timeStamp = time.time()
        privkey, mypubkey = makeKeys()
        cur = db.cursor()
        cur.execute('CREATE TABLE IF NOT EXISTS keys (FromEmail TEXT, ToEmail TEXT, SecretKey TEXT, PublicKey TEXT, OtherPublicKey TEXT, TimeStamp INT)')
        cur.execute('INSERT INTO keys VALUES(?,?,?,?,?,?)', (fromEmail,toEmail,privkey,mypubkey,otherpubkey,timeStamp))

        lid = cur.lastrowid
        print 'You have %d total keys' % lid

def getKeys(fromEmail,toEmail):
    """
    Get the key for the fromEmail -> toEmail route
    return privkey, mypubkey, otherpubkey
    """

    db = sqlite3.connect('keys.db')

    with db:

        cur = db.cursor()
        cur.execute("SELECT * FROM keys")
        rows = cur.fetchall()
        for row in rows:
            if row[0] == fromEmail and row[1] == toEmail:
                return row[2], row[3], row[4]

def listKeys():
    """
    List routes for all keys in database
    """

    db = sqlite3.connect('keys.db')

    with db:

        cur = db.cursor()
        cur.execute("SELECT * FROM keys")
        rows = cur.fetchall()
        for row in rows:
            print row[0]+' -> '+row[1]

def cloneKey(fromEmail,toEmail,newFromEmail,newToEmail):
   """
   Clone key from route fromEmail -> toEmail to new route newFromEmail -> newToEmail
   """

   db = sqlite3.connect('keys.db')

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

def changePubKey(fromEmail,toEmail,pubkey):
    """
    Change the otherpubkey for the fromEmail -> toEmail route
    """

    db = sqlite3.connect('keys.db')

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

def changeToEmail(fromEmail,oldToEmail,newToEmail):
    """
    Change the toEmail address on the fromEmail -> oldToEmail route
    """

    db = sqlite3.connect('keys.db')

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

def changeFromEmail(oldFromEmail,newFromEmail,toEmail):
    """
    Change the fromEmail address on the oldFromEmail -> toEmail route
    """

    db = sqlite3.connect('keys.db')

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

def deleteKey(fromEmail,toEmail):
    """
    Delete the fromEmail -> toEmail key from the database
    """

    db = sqlite3.connect('keys.db')

    with db:

        cur = db.cursor()
        cur.execute("SELECT * FROM keys")
        rows = cur.fetchall()
        for row in rows:
            if row[0] == fromEmail and row[1] == toEmail:
                cur.execute('DELETE FROM keys WHERE FromEmail = ? AND ToEmail = ?', (fromEmail,toEmail))

def genSharedSecret(fromEmail, toEmail):
    """
    Generate the shared secret for the fromEmail -> toEmail route
    """

    try:
        a = dh.DiffieHellman()
        privkey, mypubkey, otherpubkey = getKeys(fromEmail,toEmail)
        a.privateKey = long(privkey)
        sharedSecret = a.genSecret(long(privkey),long(otherpubkey))
        s = hashlib.sha256()
        s.update(str(sharedSecret))
        del a
        return hexlify(s.digest())
    except Exception:
        print 'Invalid public key'

def mutateKey(fromEmail,toEmail):
    """
    Change the privkey, mypubkey pair on the fromEmail -> toEmail route
    without modifying the otherpubkey.  Also, create a mutatekey.asc file
    containing the new mypubkey encrypted with the old shared secret.
    This file can be securely transmitted to the receiver for decryption
    and importation to complete the key swap process. This makes the
    old shared secret disappear completely once the receiver has imported
    the new key. (ephemeral DH - perfect forward secrecy)
    """

    db = sqlite3.connect('keys.db')

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

def getNewsTimestamp():
    """
    Get the old timestamp for reading messages from a.a.m, and replace
    the old timestamp with a new one for next time
    """

    curTimeStamp = time.time()
    db = sqlite3.connect('keys.db')

    with db:

        cur = db.cursor()
        cur.execute("SELECT * FROM news")
        rows = cur.fetchall()
        for row in rows:
            if row[0] == 1: timeStamp = int(row[1])-1
            cur.execute('UPDATE news SET LastReadTime = ? WHERE Id = 1', (curTimeStamp,))
        return timeStamp

def getListOfKeys():
    """
    Get the route and shared secret for all keys in the database.  This
    will be used to query a.a.m for any messages associated with our keys.
    """

    db = sqlite3.connect('keys.db')
    listOfKeys = []

    with db:
        cur = db.cursor()
        cur.execute("SELECT * FROM keys")
        rows = cur.fetchall()
        for row in rows:
            listOfKeys.append((row[0],row[1],genSharedSecret(row[0],row[1])))
        return listOfKeys

if __name__=="__main__":
    """
    Run an example key insertion
    """
    makeKeys()
    insertKeys(sys.argv[1], sys.argv[2], sys.argv[3])
    sharedSecret = genSharedSecret(sys.argv[1], sys.argv[2])
    print sharedSecret
    print len(sharedSecret)

