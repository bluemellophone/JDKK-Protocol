from Crypto.PublicKey import RSA
import sha

# globals, maybe define somewhere else?
MSG_LENGTH = 50
NONCE_LENGTH = 4
HASH_LENGTH = 64

# process plaintext for sending
# NONCE SHOULD ALREADY BE PART OF MSG
# Appends hash, signs, encrypts
# returns ciphertext to be sent
def outgoing(enc_k, sig_k, message):
    message = sha.append_sha256(message)
    c = sign(sig_k, message)
    c = encrypt(enc_k, c)
    return c

# process incomming messages
# decrypt, unsign, verify
def incomming(dec_k, sig_k, message, nonce):
    p = decrypt(dec_k, message)
    p = verify(sig_k, p, nonce)
    return p

# Basic RSA methods
# Do all processing as long type for consistency
def sign(key, message):
    if type(message) is str:
        message = atol(message)
    #return key.sign(message, 0)[0]
    return key.decrypt(message)
    
def unsign(key, message):
    if type(message) is str:
        message = atol(message)
    return key.encrypt(message, 0)[0]
    
    
def decrypt(key, message):
    if type(message) is str:
        message = atol(message)
    return key.decrypt(message)
    
def encrypt(key, message):
    if type(message) is str:
        message = atol(message)
    return key.encrypt(message, 0)[0]


# Verify a signed block by checking the hash, nonce
# key: Sender's public key
# message: signed plaintext
# nonce: expected value of the nonce
# Returns plaintext on success, None on failure
def verify(key, message, nonce = None):
    # unsign the message, convert to string, split off hash
    ptxt = ltoa(unsign(key, message))
    # Check message length
    if len(ptxt) != MSG_LENGTH + NONCE_LENGTH + HASH_LENGTH:
        #print "BAD MSG LEN"
        return None
    hash = sha.sha256(ptxt[:MSG_LENGTH + NONCE_LENGTH])
    # compare hashes
    if hash != ptxt[MSG_LENGTH + NONCE_LENGTH:]:
        #print "BAD HASH"
        return None
    if nonce:
        n = ptxt[MSG_LENGTH : MSG_LENGTH + NONCE_LENGTH]
        # compare nonces
        if n != nonce:
            #print "BAD NONCE"
            return None
        return ptxt[:MSG_LENGTH]
    return ptxt[:MSG_LENGTH + NONCE_LENGTH]
    
    
# String to long conversion functions
def atol(string):
    h = string.encode('hex')
    l = long(h, 16)
    return l
def ltoa(l):
    h = hex(l)[2:].strip('L')
    a = h.decode('hex')
    return a
    
