############################################################

Cryptography and Network Security II Project (JDKK-Protocol)
Project Members: Jason Parham, David Bevins, Kyle Croman, Kegham Khosdeghian

############################################################


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
simply has a collection of public keys for the users who are registered and allowed to vote.  

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


--------------- PyCrypto Usage Instructions ---------------

   - from Crypto import *
   - from Crypto import Random.*
   - from Crypto import Hash.SHA256
 

--------------------- Project Elements ---------------------

Symmetric Encryption: AES-256 (Post-Handshake Confidentiality)
Asymmetric Encryption: RSA (Two-way Authentication & Handshake Confidentiality)
Hash Function: SHA-512
Nonces: Two-Way


--------------------- Project Data Structures ---------------------

General Message Layout 
   M = m , Nonse, Padding
   Encrypt[ Sign[ M , Hash[ M ] ] ]

Handshake
   - Client Handshake = "handshake", RPI Email, SIS Password, New / First Client Nonce, Padding
      - Hashed Client Handshake = Client Handshake, Hash^SHA-512( Client Handshake )
         - Signed Hashed Client Handshake = Hashed Client Handshake, Sign^RSA-USER PRIVATE KEY( Hash of Client Handshake )   
            - RSA Encrypted Signed Hashed Client Handshake = Encrypt^RSA-SERVER PUBLIC KEY( Signed Hashed Client Handshake )
               - Encoded RSA Encrypted Signed Hashed Client Handshake = Encode^BASE64( RSA Encrypted Signed Hashed Client Handshake )

   - Server Handshake = "handshake", AES Session Key, Last Client Nonce, New / First Server Nonce, Padding
      - Hashed Server Handshake = Server Handshake, Hash^SHA-512( Server Handshake )
         - Signed Hashed Server Handshake = Hashed Server Handshake, Sign^RSA-SERVER PRIVATE KEY( Hash of Server Handshake )
            - RSA Encrypted Signed Hashed Server Handshake = Encrypt^RSA-USERNAME PUBLIC KEY( Signed Hashed Server Handshake ) ]
               - Encoded RSA Encrypted Signed Hashed Server Handshake = Encode^BASE64( RSA Encrypted Signed Hashed Server Handshake ) ]

Message
   - Ballot = User Ballot
      - Client Message = Ballot, RPI Email, SIS Password, New Client Nonce, Last Server Nonce, Padding
         - Hashed Client Message = Client Message, Hash^SHA-512( Client Message )
            - Signed Hashed Client Message = Hashed Client Message, Sign^RSA-USER PRIVATE KEY( Hash of Client Message )
               - AES Encrypted Signed Hashed Client Message = Encrypt^AES-SESSION KEY( Signed Hashed Client Message )
                  - Encoded AES Encrypted Signed Hashed Client Message = Encode^BASE64( AES Encrypted Signed Hashed Client Message )

   - Server Message = Status, Last Client Nonce, New Server Nonce, Padding
      - Hashed Server Message = Server Message, Hash^SHA-512( Server Message )
         - Signed Hashed Server Message = Hashed Server Message, Sign^RSA-SERVER PRIVATE KEY( Hash of Server Message )
            - AES Encrypted Signed Hashed Server Message = Encrypt^AES-SESSION KEY( Signed Hashed Server Message )
               - Encoded AES Encrypted Signed Hashed Server Message = Encode^BASE64( AES Encrypted Signed Hashed Server Message )


--------------------- Ballot Structure ---------------------

Base = ceil( log_2( X ) )
L = N * Base
Ballot Length (in Bits) = L Random Bits + L Ballot Bits   [ Total Length: 2 * L ]

Candidate # T Identification = Base ^ T


--------------- Vote Validation and Auditing ---------------

Upon the completion of the vote, the server administrator will publish on the web the following table:

      Hash( Public Key 1 ) -> Encrypted Ballot 1 -> Signature of Ballot 1
      Hash( Public Key 2 ) -> Encrypted Ballot 2 -> Signature of Ballot 2
      .
      .
      .
      Hash( Public Key T ) -> Encrypted Ballot T -> Signature of Ballot T   ( Where T = Number of Votes Casted and T <= X )
    
      Homomorphic Sum of all Encrypted Ballots

Any user can find their hashed public key in the table and verify that their signature of the encrypted ballot is authentic.  
If the signature is authentic, then their ballot must also be correct becuase only the user should have access to their private
key.  If the signature is not authentic, then the user can recall the election.

With all cast ballots published and the sum of the homomorphic ciphertexts also published, then the sum can be verified by any
person wishing to do so.  

The server administrator will therefore, not be able to manufacture a fake student without RPI's SIS system detecting a false 
voter because SIS can audit the published public key hashes.



   