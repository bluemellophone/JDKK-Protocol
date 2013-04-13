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

Handshake
   - Client Handshake = "handshake", RPI Email, SIS Password, New / First Client Nonce, Padding
      
      - Signed Client Handshake = Client Handshake, Sign^RSA-USER PRIVATE KEY( Client Handshake )
      
         - Hashed Signed Client Handshake = Signed Client Handshake, Hash^SHA-512( Signed Client Handshake )
      
            - RSA Encrypted Hashed Signed Client Handshake = Encrypt^RSA-SERVER PUBLIC KEY( Hashed Signed Client Handshake )

   - Server Handshake = "handshake", Last Client Nonce, New / First Server Nonce, AES Session Key, AES Session Block, Padding
      
      - Signed Server Handshake = Server Handshake, Sign^RSA-SERVER PRIVATE KEY( Server Handshake )
      
         - Hashed Signed Server Handshake = Signed Server Handshake, Hash^SHA-512( Signed Server Handshake )
      
            - RSA Encrypted Hashed Signed Server Handshake = Encrypt^RSA-USERNAME PUBLIC KEY( Hashed Signed Server Handshake ) ]

Message
   - Ballot = User Ballot
      
      - Client Message = Ballot, RPI Email, SIS Password, New Client Nonce, Last Server Nonce, Padding
         
         - Signed Client Message = Client Message, Sign^RSA-USER PRIVATE KEY( Client Message )
         
            - Hashed Signed Client Message = Signed Client Message, Hash^SHA-512( Signed Client Message )
         
               - AES Encrypted Hashed Signed Client Message = Encrypt^AES-SESSION KEY( Hashed Signed Client Message )


   - Server Message = Status, Last Client Nonce, New Server Nonce, Padding
      
      - Signed Server Message = Server Message, Sign^RSA-SERVER PRIVATE KEY( Server Message )
      
         - Hashed Signed Server Message = Signed Server Message, Hash^SHA-512( Signed Server Message )
      
            - AES Encrypted Hashed Signed Server Message = Encrypt^AES-SESSION KEY( Hashed Signed Server Message )




   