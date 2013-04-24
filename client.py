import sys
import getpass
import zmq
import util
import inspect
import sha
from Crypto.PublicKey import RSA

import rand

####################################################
############### Handshake Functions ################
####################################################

def pack_handshake(message, crypto_dict, verbose = False):
	
	# Verify required fields in crypto_dictionary
	required_keys = ["rsa_user_public_key"]

	for required_key in required_keys:
		if required_key not in crypto_dict or not crypto_dict[required_key]: 
			return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: key error, '" + str(required_key) + "' in crypto_dictionary"]

	# Hash message
	try:
		user_public_key_hash = sha.sha256(str(crypto_dict["rsa_user_public_key"]))
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> sha.sha256 ]: " + str(inst)]

	util.debug(verbose, "user_public_key_hash", user_public_key_hash)

	# Compile message
	client_message = message + ";" + user_public_key_hash

	return util.pack_handshake_general(client_message, crypto_dict, "client", verbose)

def unpack_handshake(encoded_message, crypto_dict, verbose = False):
	
	if encoded_message == "-1":
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: connection closed by server"]

	return util.unpack_handshake_general(encoded_message, crypto_dict, "client", verbose)

####################################################
############### Message Functions ##################
####################################################

def pack_message(message, crypto_dict, verbose = False):

	# Verify required fields in crypto_dictionary
	required_keys = ["rsa_user_public_key"]

	# Verify required fields in crypto_dictionary
	for required_key in required_keys:
		if required_key not in crypto_dict or not crypto_dict[required_key]: 
			return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: key error, '" + str(required_key) + "' in crypto_dictionary"]
	
	# Hash message
	try:
		user_public_key_hash = sha.sha256(str(crypto_dict["rsa_user_public_key"]))
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> sha.sha256 ]: " + str(inst)]

	util.debug(verbose, "user_public_key_hash", user_public_key_hash)

	# Compile message
	client_message = message + ";" + user_public_key_hash

	return util.pack_message_general(client_message, crypto_dict, "client", verbose)

def unpack_message(encoded_message, crypto_dict, verbose = False):
	
	if encoded_message == "-1":
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: connection closed by server"]

	return util.unpack_message_general(encoded_message, crypto_dict, "client", verbose)

####################################################
################### Init Errors ####################
####################################################

GLOBAL_VERBOSE = "-v" in sys.argv
if GLOBAL_VERBOSE:
	sys.argv.remove("-v")

for each in sys.argv:
	if "-" in each:
		print "Error: flag '", each, "' unrecognized"
		sys.exit(0)

if (len(sys.argv) != 2):
	print "Usage: python proxy.py port [-v : verbose]"
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
	"client_nonce" : False ,
	"server_nonce" : " " ,
	"rsa_user_private_key" : False ,
	"rsa_user_public_key" : False,
	"rsa_server_public_key" : False ,
	"aes_session_key" : False
}

# Temporary
crypto_dictionary["rsa_user_private_key"] = RSA.importKey(open("keys/private/voter1.private", "r").read())
crypto_dictionary["rsa_user_public_key"] = RSA.importKey(open("keys/public/voter1.public", "r").read())
crypto_dictionary["rsa_server_public_key"] = RSA.importKey(open("keys/public/server.public", "r").read())

################## Handshake ####################

handshake = pack_handshake("handshake", crypto_dictionary, GLOBAL_VERBOSE)
if handshake[0]:
	try:
		socket.send(handshake[1])
	except Exception as inst:
		print "Error [ socket.send (handshake) ]: " + str(inst)
		sys.exit(0)
else:
	print handshake[1]
	sys.exit(0)

response = unpack_handshake(socket.recv(), crypto_dictionary, GLOBAL_VERBOSE)
if response[0]:
	print "Handshake Response:", response[1]
	message = response[1].split(";")
	crypto_dictionary["aes_session_key"] = message[1]
	print "Updated AES Session Key:", crypto_dictionary["aes_session_key"]
else:
	print response[1]
	sys.exit(0)

################## Messages ####################

while True:
	message = pack_message(raw_input("Message: "), crypto_dictionary, GLOBAL_VERBOSE)
	if message[0]:
		try:
			socket.send(message[1])
		except Exception as inst:
			print "Error [ socket.send (message) ]: " + str(inst)
			sys.exit(0)
	else:
		print message[1]
		sys.exit(0)

	response = unpack_message(socket.recv(), crypto_dictionary, GLOBAL_VERBOSE)
	if response[0]:
		print "Message Response:", response[1]
	else:
		print response[1]
		sys.exit(0)


