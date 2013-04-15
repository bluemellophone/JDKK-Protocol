import sys
import math
import inspect
import getpass
import zmq
import aes
import rsa
from Crypto.PublicKey import RSA
import sha
import rand
import base64

GLOBAL_VERBOSE = True
debug_spacing = "   "

# Debug print out
def debug(verbose, var_name, var):
	try:
		if verbose:
		    print debug_spacing + "Debug [ " + str(inspect.stack()[1][3]) + " -> " +  str(var_name) + " ] (len:" + str(len(var)) + "): " + str(var)
	except Exception as inst:
		print "Error [ Debug -> " + str(inspect.stack()[1][3]) + " -> " +  str(var_name) + " ]: " + str(inst)

####################################################
################# Pack Functions ###################
####################################################

def pack_handshake(message, crypto_dict, verbose = False):
	
	# Verify required fields in crypto_dictionary
	required_keys = ["auth_username", "auth_password", "rsa_user_private_key", "rsa_server_public_key"]

	for required_key in required_keys:
		if required_key not in crypto_dict or not crypto_dict[required_key]: 
			return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: key error, '" + str(required_key) + "' in crypto_dictionary"]

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
		message_hash = sha.sha256(nonced_message)
		hashed_message = nonced_message + "|" + message_hash
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> sha.sha256 ]: " + str(inst)]

	debug(verbose, "hashed_message", hashed_message)

	# Sign message
	try:
		message_signature = str(rsa.sign(crypto_dict["rsa_user_private_key"], message_hash))
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rsa.sign ]: " + str(inst)]
	
	# Encode signature and append
	try:
		signed_message = hashed_message + "|" + base64.b64encode(message_signature)
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> base64.b64encode (signature) ]: " + str(inst)]
	
	debug(verbose, "signed_message", signed_message)

	num_message_parts = int(math.ceil( len(signed_message) / 256 )) + 1
	if verbose:
		print debug_spacing + "Debug: Signed message must be split into " + str(num_message_parts) + " messages."

	# Encrypt message
	try:
		rsa_encrypted_messages = []
		for i in range(0, num_message_parts):
			rsa_encrypted_messages.append(str(rsa.encrypt(crypto_dict["rsa_server_public_key"], signed_message[ (i * 256) : (i + 1) * 256 ])))
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rsa.encrypt ]: " + str(inst)]

	# Encode message
	try:
		encoded_messages = []
		for rsa_encrypted_message in rsa_encrypted_messages:
			encoded_messages.append(base64.b64encode(rsa_encrypted_message))
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> base64.b64encode ]: " + str(inst)]

	encoded_message = ""
	for i in range(len(encoded_messages)):
		debug(verbose, "encoded_message ( Part " + str( i + 1 ) + " )", encoded_messages[i])
		encoded_message += encoded_messages[i] + "|"
	encoded_message = encoded_message[:-1]

	debug(verbose, "encoded_message" , encoded_message)
	
	return [True, encoded_message]

def pack_message(message, crypto_dict, verbose = False):

	# Verify required fields in crypto_dictionary
	required_keys = ["auth_username", "auth_password", "server_nonce", "rsa_user_private_key", "aes_session_key"]
	
	for required_key in required_keys:
		if required_key not in crypto_dict or not crypto_dict[required_key]: 
			return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: key error, '" + str(required_key) + "' in crypto_dictionary"]

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
		message_hash = sha.sha256(nonced_message)
		hashed_message = nonced_message + "|" + message_hash
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> sha.sha256 ]: " + str(inst)]

	debug(verbose, "hashed_message", hashed_message)

	# Sign message
	try:
		message_signature = str(rsa.sign(crypto_dict["rsa_user_private_key"], message_hash))
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rsa.sign ]: " + str(inst)]
	
	# Encode signature and append
	try:
		signed_message = hashed_message + "|" + base64.b64encode(message_signature)
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> base64.b64encode (signature) ]: " + str(inst)]

	# Padding signed_message to length of 128 (AES encryption needs message to be a length of multiple 16)
	while len(signed_message) % 16 != 0:
		signed_message += "."

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
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> base64.b64encode (encrypt) ]: " + str(inst)]

	debug(verbose, "encoded_message", encoded_message)

	return [True, encoded_message]

####################################################
################ Unpack Functions ##################
####################################################

def unpack_handshake(encoded_message, crypto_dict, verbose = False):
	
	# Verify required fields in crypto_dictionary
	required_keys = ["server_nonce", "rsa_user_private_key", "rsa_server_public_key"]

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
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> base64.b64decode (encrypt) ]: " + str(inst)]

	# Decrypt message
	try:
		rsa_decrypted_message = ""
		for decoded_message in decoded_messages:
			rsa_decrypted_message += str(rsa.decrypt(crypto_dict["rsa_user_private_key"], decoded_message))
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rsa.decrypt ]: " + str(inst)]

	debug(verbose, "rsa_decrypted_message", rsa_decrypted_message)

	rdmSplit = rsa_decrypted_message.split("|")
	message_content, message_hash, message_signature = rdmSplit[0], rdmSplit[1], rdmSplit[2]

	debug(verbose, "message_content", message_content)
	debug(verbose, "message_hash", message_hash)
	debug(verbose, "message_signature", message_signature)

	# Decode signature
	try:
		message_signature = base64.b64decode(message_signature)
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> base64.b64decode (signature) ]: " + str(inst)]

	# Verify Signature
	if str(rsa.unsign(crypto_dict["rsa_server_public_key"], message_signature)) != message_hash:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: signature verification failed"]
	elif verbose:
		print debug_spacing + "Debug [ " + str(inspect.stack()[0][3]) + " ]: signature verification passed"

	# Verify Hash
	if str(sha.sha256(message_content)) != message_hash:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: hash verification failed"]
	elif verbose:
		print debug_spacing + "Debug [ " + str(inspect.stack()[0][3]) + " ]: hash verification passed"

	mcSplit = message_content.split(",")
	message, auth_username, auth_password, client_nonce = mcSplit[0], mcSplit[1], mcSplit[2], mcSplit[3]

	debug(verbose, "message", message)
	debug(verbose, "auth_username", auth_username)
	debug(verbose, "auth_password", auth_password)
	debug(verbose, "client_nonce", client_nonce)

	# Upadte crypto_dictionary
	crypto_dict["auth_username"] = auth_username
	crypto_dict["auth_password"] = auth_password
	crypto_dict["client_nonce"] = client_nonce

	return message

def unpack_message(encoded_message, crypto_dict, verbose = False):
	
	# Verify required fields in crypto_dictionary
	required_keys = ["client_nonce", "rsa_server_public_key", "aes_session_key"]

	for required_key in required_keys:
		if required_key not in crypto_dict or not crypto_dict[required_key]: 
			return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: key error, '" + str(required_key) + "' in crypto_dictionary"]

	debug(verbose, "encoded_message", encoded_message)

	# Decode message
	try:
		decoded_message = base64.b64decode(encoded_message)
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> base64.b64decode (encrypt) ]: " + str(inst)]

	# Decrypt message
	try:
		aes_decrypted_message = str(aes.aes_decrypt(crypto_dict["aes_session_key"], decoded_message))
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> aes.decrypt ]: " + str(inst)]

	debug(verbose, "aes_decrypted_message", aes_decrypted_message)

	rdmSplit = aes_decrypted_message.split("|")
	message_content, message_hash, message_signature = rdmSplit[0], rdmSplit[1], rdmSplit[2]

	# Remove any AES padding from signature
	message_signature = message_signature.strip(".")

	debug(verbose, "message_content", message_content)
	debug(verbose, "message_hash", message_hash)
	debug(verbose, "message_signature", message_signature)

	# Decode signature
	try:
		message_signature = base64.b64decode(message_signature)
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> base64.b64decode (signature) ]: " + str(inst)]

	# Verify Signature
	if str(rsa.unsign(crypto_dict["rsa_server_public_key"], message_signature)) != message_hash:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: signature verification failed"]
	elif verbose:
		print debug_spacing + "Debug [ " + str(inspect.stack()[0][3]) + " ]: signature verification passed"

	# Verify Hash
	if str(sha.sha256(message_content)) != message_hash:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: hash verification failed"]
	elif verbose:
		print debug_spacing + "Debug [ " + str(inspect.stack()[0][3]) + " ]: hash verification passed"

	mcSplit = message_content.split(",")
	message, client_nonce, server_nonce = mcSplit[0], mcSplit[1], mcSplit[2]

	debug(verbose, "message", message)
	debug(verbose, "client_nonce", client_nonce)
	debug(verbose, "server_nonce", server_nonce)

	# Verify Nonce
	if client_nonce != crypto_dict["client_nonce"]:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: nonce verification failed"]
	elif verbose:
		print debug_spacing + "Debug [ " + str(inspect.stack()[0][3]) + " ]: nonce verification passed"	

	# Upadte crypto_dictionary
	crypto_dict["server_nonce"] = server_nonce

	return message

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
	"aes_session_key" : False
}

# Temporary
crypto_dictionary["auth_username"] = "test@rpi.edu"
crypto_dictionary["auth_password"] = "pa$$w0rd"
crypto_dictionary["server_nonce"] = "43210"
crypto_dictionary["rsa_user_private_key"] = RSA.importKey(open("keys/client.private", "r").read())
crypto_dictionary["rsa_server_public_key"] = RSA.importKey(open("keys/server.public", "r").read())
crypto_dictionary["aes_session_key"] = "12345678901234567890123456789012"

handshake = pack_handshake("handshake", crypto_dictionary, GLOBAL_VERBOSE)

if handshake[0]:
	try:
		socket.send(handshake[1])
	except Exception as inst:
		print "Error [ socket.send (handshake) ]: " + str(inst)
		sys.exit(0)
else:
	print handshake[1]

msg = socket.recv()
message = unpack_handshake(msg, crypto_dictionary, GLOBAL_VERBOSE)

print message

#########################################
#########################################
#########################################

message = pack_message("ballot", crypto_dictionary, GLOBAL_VERBOSE)

if message[0]:
	try:
		socket.send(message[1])
	except Exception as inst:
		print "Error [ socket.send (message) ]: " + str(inst)
		sys.exit(0)
else:
	print message[1]

msg = socket.recv()
message = unpack_message(msg, crypto_dictionary, GLOBAL_VERBOSE)

print message


