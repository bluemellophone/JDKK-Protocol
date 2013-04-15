import sys
import inspect
import getpass
import zmq # networking library
import aes
from Crypto.PublicKey import RSA
import rsa
import sha
import rand
import base64

GLOBAL_VERBOSE = True

# Debug print out
def debug(verbose, var_name, var):
	try:
		if verbose:
		    print "Debug [ " + str(inspect.stack()[1][3]) + " -> " +  str(var_name) + " ] (len:" + str(len(var)) + "): " + str(var)
	except Exception as inst:
		print "Error [ Debug -> " + str(inspect.stack()[1][3]) + " -> " +  str(var_name) + " ]: " + str(inst)

# Pack Functions
def pack_handshake(message, crypto_dict, verbose = False):
	
	# Verify required fields in crypto_dictionary
	required_keys = ["auth_username", "auth_password", "rsa_user_private_key", "rsa_server_public_key"]

	for required_key in required_keys:
		if required_key not in crypto_dict or not crypto_dict[required_key]: 
			return [False, "Error [ " + str(inspect.stack()[0][3]) + "]: key '" + str(required_key) + "' error in crypto_dictionary"]

	# Update client nonce
	try:
		crypto_dict["client_nonce"] = "01234"
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rand ]: " + str(inst)]

	debug(verbose, "client_nonce", crypto_dict["client_nonce"])

	# Compile message
	client_message = message + "," + crypto_dict["auth_username"] + "," + crypto_dict["auth_password"]

	# Nonce
	nonced_message = client_message + "," + crypto_dict["client_nonce"] + ","

	# Padding nonced_message to length of 128
	while len(nonced_message) < 128:
		nonced_message += "."

	debug(verbose, "nonced_message", nonced_message)

	# Hash message
	try:
		hashed_message = nonced_message + "|" + sha.sha256(nonced_message)
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> sha.sha256 ]: " + str(inst)]

	debug(verbose, "hashed_message", hashed_message)

	# Sign message
	try:
		signed_message = hashed_message + "|" + str(rsa.sign(crypto_dict["rsa_user_private_key"], hashed_message))
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rsa.sign ]: " + str(inst)]
	
	debug(verbose, "signed_message", signed_message)

	# Encrypt message
	try:
		rsa_encrypted_message = str(rsa.encrypt(crypto_dict["rsa_server_public_key"], signed_message))
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rsa.encrypt ]: " + str(inst)]

	# Encode message
	try:
		encoded_message = base64.b64encode(rsa_encrypted_message)
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> base64.b64encode ]: " + str(inst)]

	debug(verbose, "encoded_message", encoded_message)

	return [True, encoded_message]

def pack_message(message, crypto_dict, verbose = False):

	# Verify required fields in crypto_dictionary
	required_keys = ["auth_username", "auth_password", "server_nonce", "rsa_user_private_key", "aes_session_key"]
	
	for required_key in required_keys:
		if required_key not in crypto_dict or not crypto_dict[required_key]: 
			return [False, "Error [ " + str(inspect.stack()[0][3]) + "]: key '" + str(required_key) + "' error in crypto_dictionary"]

	# Update client nonce
	try:
		crypto_dict["client_nonce"] = "01234"
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rand ]: " + str(inst)]

	debug(verbose, "client_nonce", crypto_dict["client_nonce"])

	# Compile message
	client_message = message + "," + crypto_dict["auth_username"] + "," + crypto_dict["auth_password"]

	# Nonce
	nonced_message = client_message + "," + crypto_dict["client_nonce"] + "," + crypto_dict["server_nonce"] + ","

	# Padding nonced_message to length of 128
	while len(nonced_message) < 128:
		nonced_message += "."

	debug(verbose, "nonced_message", nonced_message)

	# Hash message
	try:
		hashed_message = nonced_message + "|" + sha.sha256(nonced_message)
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> sha.sha256 ]: " + str(inst)]

	debug(verbose, "hashed_message", hashed_message)

	# Sign message
	try:
		signed_message = hashed_message + "|" + str(rsa.sign(crypto_dict["rsa_user_private_key"], hashed_message))

		# Padding signed_message to length of 128
		while len(signed_message) % 16 != 0:
			signed_message += "."
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rsa.sign ]: " + str(inst)]
	
	debug(verbose, "signed_message", signed_message)

	# Encrypt message
	try:
		aes_encrypted_message = str(aes.aes_encrypt(crypto_dict["aes_session_key"], signed_message))
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> aes.aes_encrypt ]: " + str(inst)]

	# Encode message
	try:
		encoded_message = base64.b64encode(aes_encrypted_message)
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> aes.aes_encrypt ]: " + str(inst)]

	debug(verbose, "encoded_message", encoded_message)

	return [True, encoded_message]

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

print "\n\n\
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

crypto_dictionary["auth_username"] = "test@rpi.edu"
crypto_dictionary["auth_password"] = "pa$$w0r|)"
crypto_dictionary["server_nonce"] = "4321"
crypto_dictionary["rsa_user_private_key"] = RSA.importKey(open("keys/client.private", "r").read())
crypto_dictionary["rsa_server_public_key"] = RSA.importKey(open("keys/server.public", "r").read())
crypto_dictionary["aes_session_key"] = "12345678901234567890123456789012"

handshake = pack_handshake("handshake", crypto_dictionary, GLOBAL_VERBOSE)

print "\n"
handshake = pack_message("message", crypto_dictionary, GLOBAL_VERBOSE)

# email = getpass.getpass("RCS ID:")
# password = getpass.getpass("SIS Password:")

# email = "parhaj@rpi.edu"
# password = "TemPa$$w0rd"

# if len(email) > 32:
# 	email = email[:32]

# if len(password) > 32:
# 	password = password[:32]

# # Handshake
# key = "1234567890123VB67890A23456789012"

# # Cast Ballot
# # msg = raw_input("Message: ")  
# msg = "This is an example message!"  
# msg = msg + "," + email + "," + password

# while len(msg) % 16 != 0:
# 	msg = msg + "."

# print msg, len(msg)
# e_msg = aes.aes_encrypt(key, msg)

# socket.send(e_msg)

# msg = socket.recv()
# print "Response:", msg
