import sys
import getpass
import zmq # networking library
import aes
import rsa
import sha
import rand

def pack_handshake(message, crypto_dict):
	if "auth_username" not in crypto_dict: return False
	if "auth_password" not in crypto_dict: return False
	if "rsa_user_private_key" not in crypto_dict: return False
	if "rsa_server_public_key" not in crypto_dict: return False

   # - Client Handshake = "handshake", RPI Email, SIS Password, New / First Client Nonce, Padding
   #    - Hashed Client Handshake = Client Handshake, Hash^SHA-512( Client Handshake )
   #       - Signed Hashed Client Handshake = Hashed Client Handshake, Sign^RSA-USER PRIVATE KEY( Hashed Client Handshake )   
   #          - RSA Encrypted Signed Hashed Client Handshake = Encrypt^RSA-SERVER PUBLIC KEY( Signed Hashed Client Handshake )




def pack_message(message, crypto_dict):
	if "auth_username" not in crypto_dict: return False
	if "auth_password" not in crypto_dict: return False
	if "server_nonce" not in crypto_dict: return False
	if "rsa_user_private_key" not in crypto_dict: return False
	if "aes_session_key" not in crypto_dict: return False
	
   # - Ballot = User Ballot
   #    - Client Message = Ballot, RPI Email, SIS Password, New Client Nonce, Last Server Nonce, Padding
   #       - Hashed Client Message = Client Message, Hash^SHA-512( Client Message )
   #          - Signed Hashed Client Message = Hashed Client Message, Sign^RSA-USER PRIVATE KEY( Hashed Client Message )
   #             - AES Encrypted Signed Hashed Client Message = Encrypt^AES-SESSION KEY( Signed Hashed Client Message )



def unpack_handshake(message, crypto_dict):
	if "rsa_user_private_key" not in crypto_dict: return False
	if "rsa_server_public_key" not in crypto_dict: return False

def unpack_message(message, crypto_dict):
	if "rsa_server_public_key" not in crypto_dict: return False
	if "aes_session_key" not in crypto_dict: return False


####################################################
################### Init Errors ####################
####################################################

if (len(sys.argv) != 2):
	print "Usage: python proxy.py port"
	sys.exit(0)

if (int(sys.argv[1]) not in range(0, 65535)):
	print "Error: invalid port given"
	sys.exit(0)

####################################################
################## Socket Setup ####################
####################################################

try:
	context = zmq.Context()
	socket = context.socket(zmq.REQ)
	socket_host = "127.0.0.1"
	socket_port = sys.argv[1]
	socket.connect("tcp://"+socket_host+":"+socket_port)
except Exception as inst:
	print "Error: socket initialization (", inst, ")"
	sys.exit(0)

print "\
-------------------------------------------------------------------------------- \n\
|     _ ___  _  ___  __ __   __   _   _             ___         _              | \n\
|  _ | |   \| |/ / |/ / \ \ / /__| |_(_)_ _  __ _  / __|_  _ __| |_ ___ _ __   | \n\
| | || | |) | ' <| ' <   \ V / _ \  _| | ' \/ _` | \__ \ || (_-<  _/ -_) '  \  | \n\
|  \__/|___/|_|\_\_|\_\   \_/\___/\__|_|_||_\__, | |___/\_, /__/\__\___|_|_|_| | \n\
|                                           |___/       |__/                   | \n\
-------------------------------------------------------------------------------- \n\
"

####################################################
#################### Main Code #####################
####################################################

crypto_dictionary = {
	"auth_username" : False ,
	"auth_password" : False ,
	"client_nonce" : False ,
	"server_nonce" :False ,
	"rsa_user_private_key" : False ,
	"rsa_server_public_key" : False ,
	"aes_session_key" : False ,
}

print crypto_dictionary

# email = getpass.getpass("RCS ID:")
# password = getpass.getpass("SIS Password:")

email = "parhaj@rpi.edu"
password = "TemPa$$w0rd"

if len(email) > 32:
	email = email[:32]

if len(password) > 32:
	password = password[:32]

# Handshake
key = "1234567890123VB67890A23456789012"

# Cast Ballot
# msg = raw_input("Message: ")  
msg = "This is an example message!"  
msg = msg + "," + email + "," + password

while len(msg) % 16 != 0:
	msg = msg + "."

print msg, len(msg)
e_msg = aes.aes_encrypt(key, msg)

socket.send(e_msg)

msg = socket.recv()
print "Response:", msg
