Cryptography and Network Security II Project (JDKK-Protocol)
Project Members:
* Jason Parham
* David Bevins
* Kyle Croman
* Kegham Khosdeghian


--------------- Library Build Instructions ---------------

* PyCrypto ( Cryptographic Library )
   - cd src/pycrypto-2.6
   - sudo ./configure
   - sudo python setup.py build
   - move src/pycrypto-2.6/build/lib.*/Crypto to project root


* PyZMQ ( Networking Library )
   - cd src/pyzmq-13.0.2
   - sudo python setup.py build
   - move src/pyzmq-13.0.2/build/lib.*/zmq to project root


--------------- PyCrypto Usage Instructions ---------------
   - from Crypto import *
   - from Crypto import Random.*
   - from Crypto import Hash.SHA256
