############################################################

Cryptography and Network Security II Project (JDKK-Protocol)
Project Members: Jason Parham, David Bevins, Kyle Croman, Kegham Khosdeghian

############################################################


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
         - Signed Hashed Client Handshake = Hashed Client Handshake, Sign^RSA-USER PRIVATE KEY( Hashed Client Handshake )   
            - RSA Encrypted Signed Hashed Client Handshake = Encrypt^RSA-SERVER PUBLIC KEY( Signed Hashed Client Handshake )

   - Server Handshake = "handshake", Last Client Nonce, New / First Server Nonce, AES Session Key, AES Session Block, Padding
      - Hashed Server Handshake = Server Handshake, Hash^SHA-512( Server Handshake )
         - Signed Hashed Server Handshake = Hashed Server Handshake, Sign^RSA-SERVER PRIVATE KEY( Hashed Server Handshake )
            - RSA Encrypted Signed Hashed Server Handshake = Encrypt^RSA-USERNAME PUBLIC KEY( Signed Hashed Server Handshake ) ]

Message
   - Ballot = User Ballot
      - Client Message = Ballot, RPI Email, SIS Password, New Client Nonce, Last Server Nonce, Padding
         - Hashed Client Message = Signed Client Message, Hash^SHA-512( Client Message )
            - Signed Hashed Client Message = Hashed Client Message, Sign^RSA-USER PRIVATE KEY( Hashed Client Message )
               - AES Encrypted Signed Hashed Client Message = Encrypt^AES-SESSION KEY( Signed Hashed Client Message )

   - Server Message = Status, Last Client Nonce, New Server Nonce, Padding
      - Hashed Server Message = Server Message, Hash^SHA-512( Server Message )
         - Signed Hashed Server Message = Hashed Server Message, Sign^RSA-SERVER PRIVATE KEY( Hashed Server Message )
            - AES Encrypted Signed Hashed Server Message = Encrypt^AES-SESSION KEY( Signed Hashed Server Message )




   