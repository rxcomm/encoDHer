#!/usr/bin/env python
"""
PyDHE - Diffie-Hellman Key Exchange in Python
Copyright (C) 2013 by Mark Loiseau

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


For more information:
http://blog.markloiseau.com/2013/01/diffie-hellman-tutorial-in-python/

Modified to use M2Crypto OpenSSL library for DH parameters.
All modifications Copyright (C) 2013 by David R. Andersen
and released under the GNU General Public License.
"""

import hashlib
from binascii import hexlify
from M2Crypto import DH
from constants import *

class DiffieHellman(object):

    def __init__(self):
        """
        Load OpenSSL dhparams from dhparams.pem file - the encoDHer distribution
        includes a 8192 bit prime in dhparams.pem. Also, strip the OpenSSL headers
        from the imported dhparams and convert to long.
        """
        self.dh = DH.load_params('/usr/local/lib/dhparams.pem')
        self.dh.gen_key()
        self.prime = long(hexlify(self.dh.p)[10:], 16)
        self.generator = int(hexlify(self.dh.g)[8:], 16)
        self.privateKey = long(hexlify(self.dh.priv)[8:], 16)
        self.publicKey = long(hexlify(self.dh.pub)[8:], 16)

    def genSecret(self, privateKey, otherKey):
        """
        Generate a shared secret using my privateKey and target's otherKey.
        We can't use OpenSSL for this because it won't let us import the
        private key. The OpenSSL DH implementation is optimized (naturally)
        for SSL/TLS encryption, so it has no idea about importing or exporting
        keys for use later. So we use this hack - but it's not too ugly!
        """
        sharedSecret = pow(otherKey, privateKey, self.prime)
        return sharedSecret

    def genKey(self, privateKey, otherKey):
        """
        Derive the shared secret, then hash it to obtain the shared secret
        used for AES256 encryption.
        """
        sharedSecret = self.genSecret(privateKey, otherKey)
        s = hashlib.sha256()
        s.update(str(sharedSecret))
        self.key = s.digest()

    def getKey(self):
        """
        Return the shared secret key
        """
        return self.key


    def showParams(self):
        """
        Show the Diffie Hellman parameters obtained from dhparams.pem file.
        """
        print ''
        print "DH Parameters:"
        p_len = len(hex(self.prime))
        print "Prime: ", hex(self.prime)[:p_len-1]
        print "Prime Length: ", str((p_len-3) * 4)+' bits'
        print "Generator: ", str(self.generator)


if __name__ == '__main__':
    """
    Run an example Diffie-Hellman exchange 
    """

    a = DiffieHellman()
    b = DiffieHellman()

    a.genKey(a.privateKey, b.publicKey)
    b.genKey(b.privateKey, a.publicKey)

    if(a.getKey() == b.getKey()):
        print "Shared keys match."
        print ''
        print "Key:", hexlify(a.key)
    else:
        print "Shared secrets didn't match!"
        print "Shared secret: ", a.genSecret(a.privateKey, b.publicKey)
        print "Shared secret: ", b.genSecret(b.privateKey, a.publicKey)

    a.showParams()
