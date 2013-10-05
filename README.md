encoDHer
===

### Introduction

encoDHer is a python utility to facilitate symmetric encryption of email
messages using the Diffie-Hellman (DH) protocol for generating a shared
secret between the sender and recipient of an email message.

Keys are stored in the database file keys.db.

### Installation requirements

The encodher package requires python-gnupg-0.3.5 or greater to function.
The latest version is documented at:

http://pythonhosted.org/python-gnupg/

Additionally, the package makes use of the Diffie Hellman class
from Mark Loiseau:

http://blog.markloiseau.com/2013/01/diffie-hellman-tutorial-in-python/

Note that this Diffie Hellman class is included in the distribution
as dh.py.

Finally, this package requires the use of gnupg to sign DH public keys for
export and to identify DH public keys for import. You will need the
GPG secret key to sign your DH keys, and the receiver's GPG public key to
verify and import DH public keys.

You should also edit the constants.py file to reflect your parameters.

Install the encoDHer module using the command:

    sudo python setup.py install

from the encoDHer directory. An executable named encodher will be created
and copied to /usr/local/bin/encodher.  The setup.py command should also
automatically install python-gnupg with most linux variants.

### Startup

To use the program, you must first initialize the keys database.  This is
accomplished with the following command:

    encodher --init

Once your database is created, you can generate keys for specific recipients
using the command:

    encodher --gen-key sender@example.org receiver@otherexample.org

where your email address is sender@example.org and your intended recipient's
email address is receiver@otherexample.org. Note that using the DH shared
secret protocol requires generating a DH secret key for each sender -> receiver
pair.  So you will probably end up with several keys in the database.

### Key distribution

You can then export your signed DH public key with the command:

    encodher --sign-pub sender@example.org receiver@otherexample.org

The output will be a signed version of your public key.  You can then
send that public key to a recipient over a non-secret channel.  An
anonymized key tablet will be developed later to facilitate DH public key
exchanges for the encodher utility, but any nonsecure channel will work.

When the recipient receives your DH public key, she can then import your
key into her database using the command:

    encodher --import textfile

where textfile is a text file containing your signed DH public key. Note
that the GPG public key used to sign your DH public key must be in her
keychain in order to verify the signature on the DH public key.

Your intended recipient should then export her signed DH public key and
send it to you.  You can then import her signed DH public key and you
are ready to communicate using symmetric key encryption with a DH shared
secret key.

### Message encryption and exchange

To encrypt a message, first create the plaintext in a file.  You can
then encrypt the contents of that message with your DH shared secret
key using the command:

    encodher --encode-email file sender@example.org receiver@otherexample.org

The email will be encrypted using symmetric aes256 encryption and output
to file.asc.  The file is an ascii-armored pgp-format file.

Upon receipt of the encrypted message, the receiver can then decrypt the
file using the command:

    encodher --decode-email file.asc sender@example.org receiver@otherexample.org

The plaintext message will then be displayed.  It is probably good to note
here that the first email address is always the message sender, and the second
is always the receiver.  So for example, if I received a message at
alice@alice.com from my buddy bob@bob.com, the correct command to decrypt the
message would be:

    encodher --decode-email file.asc bob@bob.com alice@alice.com

because bob was the sender of the email and alice was the receiver.  When I
encrypt an email to bob, the correct command is:

    encodher --encode-email file alice@alice.com bob@bob.com

because in this case alice is the sender and bob the receiver.

### Key cloning

It is possible to clone your DH secret key to another route. This functionality
is useful when, for example you want to post your DH public key on a
key table or other public place to enable multiple people to send you
encrypted email.  You clone keys by using the command:

    encodher --clone-key old1@first.org old2@second.org new1@third.org new2@fourth.org

This will clone your secret key from the route old1@first.org -> old2@second.org
to the new route new1@third.org -> new2@fourth.org.  When someone wants
to use your posted DH public key to send you encrypted email, they will send
you their DH public key over any insecure channel.  You can then import their
public key and the new route will have a completely different shared secret
than the old route does.

### Other options

Various options for key management exist.  The following list of options
can be obtained by executing encodher without any arguments.

    Options:
     --init, -i: initialize keys.db database
     --import, -m: import signed public key
     --mutate-key, -a: mutate DH secret key
     --sign-pub, -s: sign your own public key
     --change-toemail, -t: change toEmail on key
     --change-fromemail, -f: change fromEmail on key
     --change-pubkey, -p: change public key for fromEmail -> toEmail
     --encode-email, -e: symmetrically encode a file for fromEmail -> toEmail
     --decode-email, -d: symmetrically decode a file for fromEmail -> toEmail
     --list-keys, -l: list all keys in database
     --gen-secret, -c: generate shared secret for fromEmail -> toEmail
     --gen-key, -n: generate a new key for fromEmail -> toEmail
     --get-key, -g: get key for fromEmail -> toEmail from database
     --fetch-aam, -h: fetch messages from alt.anonymous.messages newsgroup
     --clone-key, -y: clone key from one route to another
     --rollback, -b: roll back the a.a.m last read timestamp

### Perfect forward secrecy

The primary reason for using symmetric encryption with DH shared secrets
for email exchanges is to provide for perfect forward secrecy (PFS).  If, after
an exchange, the DH keys are destroyed by both parties, any messages
encrypted with these keys can no longer be read, achieving PFS. Users can
change their keys to take advantage of PFS by executing:

    encodher --mutate-key sender@example.org receiver@example.org

This will destroy sender@example.org's old DH secret key, generate a new
DH secret key and export the corresponding new DH public key encrypted with the
old DH shared secret.  This encrypted file can be emailed to the receiver,
who can then decrypt the file and import the key using the --import option.
If an unencrypted version of the new signed DH public key is desired,
the --sign-pub option can be used. Once the new DH public key has been
imported by the receiver, no one (including the original sender and receiver)
will be able to read the old messages. Change keys carefully.

### Anonymous communication

If anonymous communication is desired, encodher presents an option to encode
the email for transmission using the mixmaster network.  Once the appropriate
mixmaster headers are added (by answering affirmatively to the question about
sending anonymously), the message can be dispatched to the
alt.anonymous.messages newsgroup with the command:

    mixmaster -c 1 < message.asc

where message.asc contains the encrypted message and plaintext headers. Note
that you must have the mixmaster https://github.com/crooks/mixmaster package
installed and stats updated for this to work. Most linux flavors have this
package available.

To receive messages sent to you at a.a.m using a DH key of yours, you can
execute the command:

    encodher --fetch-aam

This will fetch and decrypt all a.a.m messages for each of the keys in your
database.

### Building an executable

To build an executable in the encoDHer directory, change to the encoDHer
directory and execute the command:

    sudo python setup.py install

This will create the executable named 'encodher'. You can then move it anywhere
in your path for it to be usable. You will need to install the python gnupg library
(version 0.3.5 or greater - see the link above) before the executable will run.

If you don't want to download the entire source, the executable should run on
most linux systems without any changes.  So you can grab a copy using wget:

    wget https://github.com/rxcomm/encoDHer/raw/master/encodher

make it executable:

    chmod +x encodher

and it should run. To extract the python source from the executable, rename it
as a .zip archive and unzip it, e.g.:

    mv encodher encodher.zip
    unzip encodher.zip
