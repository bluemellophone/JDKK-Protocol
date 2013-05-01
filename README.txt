############################################################

Cryptography and Network Security II Project (JDKK-Protocol)
Project Members: Jason Parham, David Bevins, Kyle Croman, Kegham Khosdeghian

############################################################

--------------- Notes ---------------

The client program has to associate a voter with a RSA keypair.  In reality, there would exist only one provate key on a machine
for the purpose of voting.  This is not a realistic, practical, or an efficient implimentation.  For testing purposes, the client
asks for the voter number of the user so that it can loate that person's RSA public / private keypair.

keygen.py creates RSA keys for each voter and the server and also creates a homomorphic key using RSA primatives.  To add voters, 
adjust the parameter in the keygen.py file and execute.

The authors note that this election server has a limited application for the purposes of a school election.  For a national-level
election, this software implimentation will likely need features that mirror real-world malware, like: packed executable,
anti-dissasembly / anti-debugging / anti-virtualization, integrity checking, metamorphic / polymorphic engines, etc.  Such 
implementations are beyond the scope of this course and are quite evil for the analyzing team.

Candidates are determined by the list of candidate names in util.py.  The code is generaic enough to support the addition or deletion
of the sample candidates.  The code also gathers the number of registered voters from the number of RSA public keys "given" form SIS
and stored in keys/public/voter#.public


--------------- Protocol Parameters ---------------

X = Number of Registered Voters
N = Number of Candidates


--------------- Voter Registration ---------------

Voters who wish to vote in the election must generate a RSA public / private keypair on their personal machine.  Once the keypair 
has been generated, a user must login to RPI's SIS and upload their public key.  SIS will maintain a record of valid public keys 
for valid students.  Only students who have access to SIS and are current RPI stuents are allowed to upload a public key.  Once 
the voting is to begin, the collection of registered public keys ( with identifying information stripped ) is delivered to the 
server administrator ( Mal ).

It should be stressed that the collection of public keys has no associating identifying information.  The server administrator
simply has a collection of public keys for the users who are registered and allowed to vote.  The server administrator cannot
identify a specific voter based on their public key.

The server administrator, upon receiving these public keys, will generate a table of public keys and their corresponding hashes
of the public keys.  For example:
   
   Hash( Public Key 1 ) -> Key 1
   Hash( Public Key 2 ) -> Key 2
   .
   .
   .
   Hash( Public Key X ) -> Key X

The hashed key table is used to efficiently look up and authenticate users who connect to the server as authentic, registered 
voters.  


--------------- Library Build Instructions ---------------

PyCrypto ( Cryptographic Library )
   - cd src/pycrypto-2.6
   - sudo ./configure
   - sudo python setup.py build
   - move src/pycrypto-2.6/build/lib.*/Crypto to project root

PyZMQ ( Networking Library )
   - cd src/pyzmq-13.0.2
   - sudo python setup.py build
   - move src/pyzmq-13.0.2/build/lib.*/zmq to project root


--------------------- Project Elements ---------------------

Symmetric Encryption: AES-256 (Post-Handshake Confidentiality)
Asymmetric Encryption: RSA-2048 (Two-way Authentication & Handshake Confidentiality)
Hash Function: SHA-512
Nonces: Two-Way Random Numbers
Homomorphic Encryption: Paillier-2048


--------------------- Project Data Structures ---------------------

General Message Layout 
   M = m , Nonse, Padding
   Encrypt[ Sign[ M , Hash[ M ] ] ]

Handshake
   - Client Handshake = "handshake"; Client Public Key Hash, New / First Client Nonce, Padding
      - Hashed Client Handshake = Client Handshake | Hash^SHA-512( Client Handshake )
         - Signed Hashed Client Handshake = Hashed Client Handshake | Sign^RSA-USER PRIVATE KEY( Hash of Client Handshake )   
            - RSA Encrypted Signed Hashed Client Handshake = Encrypt^RSA-SERVER PUBLIC KEY( Signed Hashed Client Handshake )
               - Encoded RSA Encrypted Signed Hashed Client Handshake = Encode^BASE64( RSA Encrypted Signed Hashed Client Handshake )

   - Server Handshake = "handshake"; AES Session Key; New AES Session ID, Last Client Nonce, New / First Server Nonce, Padding
      - Hashed Server Handshake = Server Handshake | Hash^SHA-512( Server Handshake )
         - Signed Hashed Server Handshake = Hashed Server Handshake | Sign^RSA-SERVER PRIVATE KEY( Hash of Server Handshake )
            - RSA Encrypted Signed Hashed Server Handshake = Encrypt^RSA-USERNAME PUBLIC KEY( Signed Hashed Server Handshake ) ]
               - Encoded RSA Encrypted Signed Hashed Server Handshake = Encode^BASE64( RSA Encrypted Signed Hashed Server Handshake ) ]

Message
   - Ballot = User Ballot
      - Client Message = Ballot; Client Public Key Hash, New Client Nonce, Last Server Nonce, Padding
         - Hashed Client Message = Client Message, | Hash^SHA-512( Client Message )
            - Signed Hashed Client Message = Hashed Client Message | Sign^RSA-USER PRIVATE KEY( Hash of Client Message )
               - AES Encrypted Signed Hashed Client Message = Encrypt^AES-SESSION KEY( Signed Hashed Client Message )
                  - Encoded AES Encrypted Signed Hashed Client Message = Last AES Session ID . Encode^BASE64( AES Encrypted Signed Hashed Client Message )

   - Server Message = Status; New AES Session ID, Last Client Nonce, New Server Nonce, Padding
      - Hashed Server Message = Server Message, Hash^SHA-512( Server Message )
         - Signed Hashed Server Message = Hashed Server Message, Sign^RSA-SERVER PRIVATE KEY( Hash of Server Message )
            - AES Encrypted Signed Hashed Server Message = Encrypt^AES-SESSION KEY( Signed Hashed Server Message )
               - Encoded AES Encrypted Signed Hashed Server Message = Encode^BASE64( AES Encrypted Signed Hashed Server Message )


--------------------- Ballot Structure ---------------------

Base = ceil( log_2( X ) ) + 1
Ballot = 2 ^ (Base * Candidate Number)


--------------- Vote Validation and Auditing ---------------

Upon the completion of the vote, the server administrator will publish on the web the following table (public.txt):

   Encode^BASE^64( Public Key 1 ) -> Homomorphically Encrypted Ballot 1 -> Encode^BASE^64( Signature of Ballot 1 )
   Encode^BASE^64( Public Key 2 ) -> Homomorphically Encrypted Ballot 2 -> Encode^BASE^64( Signature of Ballot 2 )
   .
   .
   .
   Encode^BASE^64( Public Key T ) -> Homomorphically Encrypted Ballot T -> Encode^BASE^64( Signature of Ballot T )  ( Where T = Number of Votes Casted and T <= X )
    
   Homomorphic Sum of all Encrypted Ballots -> Homomoprhic Private Key

Any user can find their public key in the table and verify that their signature of the encrypted ballot is authentic.  
If the signature is authentic, then their ballot must also be correct becuase only the user should have access to their private
key.  If the signature is not authentic, then the user can recall the election.

With all cast ballots published and the sum of the homomorphic ciphertexts also published, then the sum can be verified by any
person wishing to do so.  Finally, the homomorphic private key is published so that the community can collectively verify the
vote and the total sum.  This scheme only works as long as the public keys have no personal identifying information associated
with them.  It should be stressed that SIS is a trusted authority because they are the one entity that organizes voter
registration.

The server administrator will be able to manufacture a fake student without RPI's SIS system detecting a false voter public key.
The server adminsitrator will also not be able to change a ballot for a particular student because it would be detectable by the 
voter; only the voter maintains their own private key and therefore only a voter can sign their ballot.  The server administrator
will also not be able to add registered voters who decide not to actually vote because they can detect their vote being cast.
In conclusion, the server administrator will not be able to manufacture election results because at the end of the election the
homomorphic private key is also published; this may seem as counterintuitive but we are willing to have a perfectly auditable
election at the expense of overhead and the slightly increased chance of voter coercion.


--------------- Conclusion ---------------

The election results are stored in public.txt and the homomorphic sum is stored in votes.txt.  The following three things are 
published at the end of the election: 
   - public.txt
   - votes.txt
   - homomorphic.private

To find the results of the election, simply run tally.py

   
