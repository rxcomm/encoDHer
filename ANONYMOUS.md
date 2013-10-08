Understanding encoDHer
===

### 1. Threat model

Alice and Bob want to communicate.  They do not want others to
read their communication, and they do not want each other to
know their identities.  Further, they do not want others to
know that they are communicating.

They also fear a malevolent authority taking over a nymserver,
which is the old way of handling this type of communication.
The owner of the nymserver has the set of encryption keys
that is used to guarantee anonymity, and so is vulnerable to
an attack from authority.

### 2. Overview of communication cycle

Alice and Bob decide to communicate.  Their communication is
somewhat voluminous (several few-page pdf's are being exchanged).
Thus, irc/instant messaging type communication is not optimal -
rather email-type communication is required.

Prior to any communication occurring, Alice and Bob will have
created GPG key pairs for themselves that are not posted on any
public media (including keyservers) that can be traced back
to them.  We will assume the uids for these keys are @alice and
@bob (GPG can create these uids with the --allow-freeform-uid
option). Further, both Bob and Alice generate a Diffie-Hellmann
key pair for themselves.

They then sign their DH public key with their GPG private key,
and post both the signed DH public key as well as their GPG
public key on an anonymized key tablet. They can also provide
this data via other anonymized distribution channels - e.g.
anonymized irc/im.

To start communicating, Alice and Bob need to create
a shared secret that will be valid for at least one message.
The shared secret will be created by each grabbing the
other's DH and GPG public keys from the key tablet or other
anonymized distribution channel.  They then create a
shared secret via DH protocol using their DH private key and
the other's DH public key.

Alice then creates her plaintext message to Bob. If she also
wants perfect forward secrecy, she also generates a new
DH key pair, and adds the new DH public key to the bottom
of her plaintext message. She encrypts her plaintext message
with symmetric AES256 encryption using the DH shared secret
as the encryption key. She then creates a hashed subject
(hsub) for the doubly-encrypted message using a part of the
DH shared secret as her hsub passphrase. Finally, she submits
the doubly-encrypted message with hsub subject to
alt.anonymous.messages via mixmaster and tor.

For PFS, Alice then securely destroys her first DH key pair.

To receive the message from Alice, Bob searches
alt.anonymous.messages via tor using the DH shared
secret as his hsub passphrase.  When he finds the
message, he decrypts the message using the DH shared secret
(symmetric decryption) He then reads the plaintext message
and recovers Alice's new DH public key.

To respond, Bob generates a new plaintext message and
new DH keypair.  He adds his new DH public key to
the bottom of his plaintext message and encrypts
the message with a new DH shared secret using his
first DH private key and Alice's new DH public key,
He then creates an hsub using a part of the new DH shared
secret as passphrase and submits the message with hsub
subject to alt.anonymous.messages via mixmaster and tor.

For PFS, Bob then securely destroys his first DH key pair.

Alice then searches alt.anonymous.messages via tor with
the DH shared secret generated from her second DH private
key and Bob's first DH public key.  When she finds
the message, she decrypts it, reads the plaintext
and gets Bob's new DH public key. If she desires
to respond, she generates a new plaintext and DH
keypair and the cycle continues.

### Notes:

1. hsub is not strictly required.  The alternative
is simply to attempt to decrypt all messages from
alt.anonymous.messages.

2. One problem with this protocol is that messaging
must be sequential: Alice -> Bob -> Alice -> Bob ...
The protocol could be modified so that DH shared
secrets were valid e.g. for some pre-agreed upon
time period.  Then Alice could send multiple
messages to Bob during that time period.  The cost
is of course, reduction in perfect forward secrecy.

3. In practice, when PFS it is easier to generate a new DH secret
key and send it as a separate message, rather than including
it in the plaintext message.  This is actually the way
that encoDHer has implemented PFS.  The option --mutate-key
is used to do this.

### FAQ:

1. Why symmetric encryption?  Isn't public-key good
enough if we use --throw-keyids as an option to
GPG?

  * The symmetric encryption with dynamic DH shared
secrets provides perfect forward secrecy.  Once
the DH key pair is destroyed, old messages can't be
read, even if either Alice or Bob is compromised.
This would not be the case if we used only public
key encryption.

The one possible exception to this is the first
two messages - since both DH public keys are assumed
to be available long-term on a key tablet, if
either Alice or Bob is compromised, the first two
messages could be read by an attacker.  To compensate
for this, it is recommended that the first two messages
be throw-away messages, used only to exchange new
DH public keys.

2. Why use mixmaster/tor combination to submit
messages to alt.anonymous.messages? Isn't one
or the other good enough?

  * Mixmaster is vulnerable to tagging attacks. Using
tor as a submission channel to mixmaster prevents
tagged messages from being traced to the sender. Tor
is vulnerable to traffic analysis due to its low
latency.  Using high-latency mixmaster reduces the
effectiveness of these attacks.

Note that the submission to the mixmaster network is
via smtp.  As a result, this should be done using ssl
over tor to further prevent traffic analysis and mitm
attacks. Also, tor blocks port 25, so open smtp can't
be done anyway.

3. Why use tor to search alt.anonymous.messages? If
all messages are downloaded, no one can tell which of
them you are interested in, can they?

  * That is true, but our threat model includes not wanting
anyone to know that Alice and Bob are communicating.
tor anonymizes the search of alt.anonymous.messages.

4. Why use alt.anonymous.messages at all?  Couldn't
Alice send her message directly to Bob?

  * Yes, but that is difficult to do anonymously.

5. What happens if the chain is broken - and one
of the messages gets lost.  Doesn't that break the
sequential DH shared secret bootstrapping?

  * Yes.  You would simply start over if this happened.

6. What does a typical message to be submitted to
alt.anonymous.messages look like?

  * Here is an example.  The message would be submitted
via mixmaster using the command:

     mixmaster -c1 < message.txt

where message.txt contains the following contents:

To: mail2news@dizum.com,mail2news@m2n.mixmin.net  
Subject: c73dc0a5f92ca70b0b0a0ee98eaec862901f25f3cc6796e2  
Newsgroups: alt.anonymous.messages  
X-No-Archive: Yes  

-----BEGIN PGP MESSAGE-----

jA0ECQMIJ1NWy0QcizvU0usB6xNTTWPjDmgEnRiI1kU/ROrWkeXKpMsO//VLYhqs
kogetdM0JjLQuFHJBdEoLiR2jP/L/Avaer1DDq0MymnolasNhq5U2uOZjC6O8u3a
/RPgt3iYSiMnTQbW+cLN+TBs3pO4fasVFJ0tTHJZkse+daCMmRlm3c585mFdwuNE
0ReQFJnBgUy0wFQGb4SAhVlOZhRDFq89vYCbbo3IoPUbycjuV3yjYNBlnqOnC9SL
...
6fvQLr+rx01QrvXodriMG6gbUKh6342z9Yhua8aN+MtQMwWHpTVf4eP8xPhxjJF6
RhSOkC/xdzthjp5g4Ii7yJ0FsuKX/APubMHIw3aNPDjJ4+eUN/Q2KrcQIgoAM661
DDGBFx03kxMIlVktkF+zZ12Bnxo+YdE1I64ONVv3v38Urc07qperf1eGo5kfvwQI
mp/CAc7AhgdYg7TRasP3v6PRj3Ac+hXObUlI98mNyvOnqhDAKtv9gbGyN2n8RHmK
IOck
=AUXa
-----END PGP MESSAGE-----

The included headers will:

1) send the message to two different mail2news servers  
2) have hsub subject c73...  
3) will be posted at alt.anonymous.messages  
4) will be (hopefully - although it doesn't really matter)
   unarchived in one week.
