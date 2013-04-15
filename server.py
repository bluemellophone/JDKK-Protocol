import sys
import inspect
import zmq
import aes
import rsa
from Crypto.PublicKey import RSA
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
def unpack_handshake(encoded_message, crypto_dict, verbose = False):
	
   # - Client Handshake = "handshake", RPI Email, SIS Password, New / First Client Nonce, Padding
   #    - Hashed Client Handshake = Client Handshake, Hash^SHA-512( Client Handshake )
   #       - Signed Hashed Client Handshake = Hashed Client Handshake, Sign^RSA-USER PRIVATE KEY( Hashed Client Handshake )   
   #          - RSA Encrypted Signed Hashed Client Handshake = Encrypt^RSA-SERVER PUBLIC KEY( Signed Hashed Client Handshake )

	# Verify required fields in crypto_dictionary
	required_keys = ["client_nonce", "rsa_user_public_key", "rsa_server_private_key"]

	for required_key in required_keys:
		if required_key not in crypto_dict or not crypto_dict[required_key]: 
			return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: key error, '" + str(required_key) + "' in crypto_dictionary"]

	debug(verbose, "encoded_message", encoded_message)

	# Split messages
	encoded_messages = encoded_message.split("|")

	# Decode message
	try:
		decoded_messages = []
		for encoded_message in encoded_messages:
			decoded_messages.append(base64.b64decode(encoded_message))
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> base64.b64decode ]: " + str(inst)]

	# Decrypt message
	try:
		rsa_decrypted_message = ""
		for decoded_message in decoded_messages:
			rsa_decrypted_message += str(rsa.decrypt(crypto_dict["rsa_server_private_key"], decoded_message))
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rsa.decrypt ]: " + str(inst)]

	debug(verbose, "rsa_decrypted_message", rsa_decrypted_message)









	# # Update client nonce
	# try:
	# 	crypto_dict["server_nonce"] = "43210"
	# except Exception as inst:
	# 	return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rand ]: " + str(inst)]

	# debug(verbose, "server_nonce", crypto_dict["server_nonce"])

	# # Compile message
	# client_message = message + "," + crypto_dict["auth_username"] + "," + crypto_dict["auth_password"]

	# # Nonce
	# nonced_message = client_message + "," + crypto_dict["client_nonce"] + ","

	# # Padding nonced_message to length of 128
	# while len(nonced_message) < 128:
	# 	nonced_message += "."

	# debug(verbose, "nonced_message", nonced_message)

	# # Hash message
	# try:
	# 	hashed_message = nonced_message + "|" + sha.sha256(nonced_message)
	# except Exception as inst:
	# 	return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> sha.sha256 ]: " + str(inst)]

	# debug(verbose, "hashed_message", hashed_message)

	# # Sign message
	# try:
	# 	signed_message = hashed_message + "|" + str(rsa.sign(crypto_dict["rsa_user_private_key"], hashed_message))
	# except Exception as inst:
	# 	return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rsa.sign ]: " + str(inst)]
	
	# debug(verbose, "signed_message", signed_message)


	# debug(verbose, "encoded_message", encoded_message)

	# return [True, encoded_message]

	return True


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
	socket = context.socket(zmq.REP)
	socket_host = "127.0.0.1"
	socket_port = sys.argv[1]
	socket.bind("tcp://"+socket_host+":"+socket_port)
except Exception as inst:
	print "Error: socket initialization (", inst, ")"
	sys.exit(0)

print "\
------------------------------------------------------------------------------- \n\
|     _ ___  _  ___  __ __   __   _   _             ___                       | \n\
|  _ | |   \| |/ / |/ / \ \ / /__| |_(_)_ _  __ _  / __| ___ _ ___ _____ _ _  | \n\
| | || | |) | ' <| ' <   \ V / _ \  _| | ' \/ _` | \__ \/ -_) '_\ V / -_) '_| | \n\
|  \__/|___/|_|\_\_|\_\   \_/\___/\__|_|_||_\__, | |___/\___|_|  \_/\___|_|   | \n\
|                                           |___/                             | \n\
------------------------------------------------------------------------------- \n\
"

####################################################
#################### Main Code #####################
####################################################

crypto_dictionary = {
	"client_nonce" : False ,
	"server_nonce" :False ,
	"rsa_user_public_key" : False ,
	"rsa_server_private_key" : False ,
	"aes_session_key" : False
}

# Temporary
crypto_dictionary["client_nonce"] = "01234"
crypto_dictionary["server_nonce"] = "43210"
crypto_dictionary["rsa_user_public_key"] = RSA.importKey(open("keys/client.public", "r").read())
crypto_dictionary["rsa_server_private_key"] = RSA.importKey(open("keys/server.private", "r").read())
crypto_dictionary["aes_session_key"] = "12345678901234567890123456789012"

msg = socket.recv()

unpack_handshake(msg, crypto_dictionary, GLOBAL_VERBOSE)



