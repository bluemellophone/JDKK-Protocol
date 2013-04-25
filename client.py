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

def encodeMessage(message):
	message = message.replace(".", "^__PERIOD__^")
	message = message.replace(",", "^__COMMA__^")
	message = message.replace(";", "^__SEMICOLON__^")
	message = message.replace("|", "^__PIPE__^")
	return message

def pack_handshake(message, crypto_dict, verbose = False):
	
	if verbose:
		print "\n"

	# Compile message
	client_message = encodeMessage(message) + ";" + crypto_dict["rsa_user_public_key_hash"]

	return util.pack_handshake_general(client_message, crypto_dict, "client", verbose)

def unpack_handshake(encoded_message, crypto_dict, verbose = False):
	
	if verbose:
		print "\n"
		
	if encoded_message == "-1":
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: connection closed by server"]

	return util.unpack_handshake_general(encoded_message, crypto_dict, "client", verbose)

####################################################
############### Message Functions ##################
####################################################

def pack_message(message, crypto_dict, verbose = False):

	if verbose:
		print "\n"
		
	# Compile message
	client_message = encodeMessage(message) + ";" + crypto_dict["rsa_user_public_key_hash"]

	return util.pack_message_general(client_message, crypto_dict, "client", verbose)

def unpack_message(encoded_message, crypto_dict, verbose = False):
	
	if verbose:
		print "\n"
		
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

voter_id = -1
while voter_id < 0 or voter_id > 10:
	voter_id = int(raw_input("What is your voter number?"))

temp = RSA.importKey(open("keys/public/voter" + str(voter_id) + ".public", "r").read())
temp_hash = sha.sha256(str(temp.n))

crypto_dictionary = {
	"client_nonces" : { temp_hash : False } ,
	"server_nonces" : { temp_hash : "0" } , # Default Server Nonce to begin with
	"rsa_user_public_keys" : { temp_hash: temp } ,
	"rsa_user_private_key" : RSA.importKey(open("keys/private/voter" + str(voter_id) + ".private", "r").read()) ,
	"rsa_server_public_key" : { temp_hash : RSA.importKey(open("keys/public/server.public", "r").read()) } ,
	"aes_session_keys" : { temp_hash : False },
	"client_aes_id" : False,
	"rsa_user_public_key_hash" : temp_hash
}

################## Handshake ####################

if GLOBAL_VERBOSE or True:
	print "User Public Key Hash:", crypto_dictionary["rsa_user_public_key_hash"]

handshake = pack_handshake("handshake", crypto_dictionary, GLOBAL_VERBOSE)
if handshake[0]:
	try:
		socket.send("." + handshake[1])
	except Exception as inst:
		print "Error [ socket.send (handshake) ]: " + str(inst)
		sys.exit(0)
else:
	print handshake[1]
	sys.exit(0)

response = unpack_handshake(socket.recv(), crypto_dictionary, GLOBAL_VERBOSE)
if response[0]:
	message = response[1].split(";")
	print "Handshake Response:", message[0]
	crypto_dictionary["aes_session_keys"][crypto_dictionary["rsa_user_public_key_hash"]] = message[1]
	crypto_dictionary["client_aes_id"] = message[2]

	if GLOBAL_VERBOSE:
		print "Updated AES Session Key:", crypto_dictionary["aes_session_keys"][crypto_dictionary["rsa_user_public_key_hash"]]
		print "Updated AES Session ID:", crypto_dictionary["client_aes_id"]
else:
	print response[1]
	sys.exit(0)

################## Messages ####################

while True:
	message = pack_message(raw_input("Message: "), crypto_dictionary, GLOBAL_VERBOSE)
	if message[0]:
		try:
			util.debug(GLOBAL_VERBOSE, "client_aes_id", crypto_dictionary["client_aes_id"])
			socket.send(crypto_dictionary["client_aes_id"] + "." + message[1])
		except Exception as inst:
			print "Error [ socket.send (message) ]: " + str(inst)
			sys.exit(0)
	else:
		print message[1]
		sys.exit(0)

	response = unpack_message(socket.recv(), crypto_dictionary, GLOBAL_VERBOSE)
	if response[0]:
		message = response[1].split(";")
		print "Message Response:", message[0]
		crypto_dictionary["client_aes_id"] = message[1]

		if GLOBAL_VERBOSE:
			print "Updated AES Session ID:", crypto_dictionary["client_aes_id"]
	else:
		print response[1]
		sys.exit(0)


