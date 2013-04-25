import sys
import zmq
import util
import inspect
import rand
import sha
from Crypto.PublicKey import RSA

####################################################
############### Handshake Functions ################
####################################################

def decodeMessage(message):
	message = message.replace("^__PERIOD__^", ".")
	message = message.replace("^__COMMA__^", ",")
	message = message.replace("^__SEMICOLON__^", ";")
	message = message.replace("^__PIPE__^", "|")
	return message

def pack_handshake(message, crypto_dict, verbose = False):
   	
	if verbose:
		print "\n"
		
	# Update AES session key
	try:
		crypto_dict["aes_session_keys"][crypto_dict["rsa_user_public_key_hash"]] = str(rand.rand_byte(32))[:32]
		crypto_dict["aes_session_ids"][crypto_dict["rsa_user_public_key_hash"]] = str(rand.rand_byte(32))[:32]
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rand ]: " + str(inst)]

	util.debug(verbose, "aes_session_key", crypto_dict["aes_session_keys"][crypto_dict["rsa_user_public_key_hash"]])
	util.debug(verbose, "aes_session_id", crypto_dict["aes_session_ids"][crypto_dict["rsa_user_public_key_hash"]])

	# Compile message
	server_message = message + ";" + crypto_dict["aes_session_keys"][crypto_dict["rsa_user_public_key_hash"]] + ";" + crypto_dict["aes_session_ids"][crypto_dict["rsa_user_public_key_hash"]]

	return util.pack_handshake_general(server_message, crypto_dict, "server", verbose)

def unpack_handshake(encoded_message, crypto_dict, verbose = False):
	
	if verbose:
		print "\n"
		
	return util.unpack_handshake_general(encoded_message, crypto_dict, "server", verbose)

####################################################
############### Message Functions ##################
####################################################

def pack_message(message, crypto_dict, verbose = False):
	
	if verbose:
		print "\n"

	# Update AES session key
	try:
		crypto_dict["aes_session_ids"][crypto_dict["rsa_user_public_key_hash"]] = str(rand.rand_byte(32))[:32]
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rand ]: " + str(inst)]

	util.debug(verbose, "aes_session_id", crypto_dict["aes_session_ids"][crypto_dict["rsa_user_public_key_hash"]])

		
	server_message = message + ";" + crypto_dict["aes_session_ids"][crypto_dict["rsa_user_public_key_hash"]]

	return util.pack_message_general(server_message, crypto_dict, "server", verbose)

def unpack_message(encoded_message, crypto_dict, verbose = False):
	
	if verbose:
		print "\n"
		
	return util.unpack_message_general(encoded_message, crypto_dict, "server", verbose)

####################################################
################### Init Errors ####################
####################################################

GLOBAL_VERBOSE = "-v" in sys.argv
if GLOBAL_VERBOSE:
	sys.argv.remove("-v")

for each in sys.argv:
	if "-" in each:
		print "Error: flag '" + each + "' unrecognized"
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
	socket = context.socket(zmq.REP)
	socket_host = "127.0.0.1"
	socket_port = sys.argv[1]
	socket.bind("tcp://"+socket_host+":"+socket_port)
except Exception as inst:
	print "Error: socket initialization (", inst, ")"
	sys.exit(0)

print "\n\n\
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

# Open public keys
c = 1
registered_voters_public_keys = {}
while True:
	temp_filename = "keys/public/voter" + str(c) + ".public"
	try:
	   with open(temp_filename ): pass
	except IOError:
	   break

	temp_key = RSA.importKey(open(temp_filename , "r").read())
	temp_hash = sha.sha256(str(temp_key.n))
	registered_voters_public_keys[temp_hash] = temp_key
	c += 1

if GLOBAL_VERBOSE: 
	print "RSA Public Key Hash Dictionary:"
	print registered_voters_public_keys
	print "\n\n"

crypto_dictionary = {
	"client_nonces" : {} ,
	"server_nonces" : {} ,
	"rsa_user_public_keys" : registered_voters_public_keys ,
	"rsa_server_private_key" : RSA.importKey(open("keys/private/server.private", "r").read()) ,
	"aes_session_keys" : {} ,
	"aes_session_ids" : {} ,
	"rsa_user_public_key_hash" : False
}


while True:

	try:
		received = socket.recv()

		if received[0] == ".":
			################## Handshake ####################
			received = received[1:]

			handshake = unpack_handshake(received, crypto_dictionary, GLOBAL_VERBOSE)
			if handshake[0]: 
				message = handshake[1].split(";")
				print "Handshake Received:", decodeMessage(message[0])

				if GLOBAL_VERBOSE:
					print "User Public Key Hash:", message[1]

			else:
				print handshake[1]
				socket.send("-1")
				# sys.exit(0)

			response = pack_handshake("handshake", crypto_dictionary, GLOBAL_VERBOSE)
			if response[0]:
				try:
					socket.send(response[1])
				except Exception as inst:
					print "Error [ socket.send (handshake) ]: " + str(inst)
					# sys.exit(0)
			else:
				print response[1]
				# sys.exit(0)

		else:
			################## Messages ####################

			message = unpack_message(received, crypto_dictionary, GLOBAL_VERBOSE)
			if message[0]:
				message = message[1].split(";")
				print "Message Received:", decodeMessage(message[0])

				if GLOBAL_VERBOSE:
					print "User Public Key Hash:", message[1]
			else:
				print message[1]
				socket.send("-1")
				# sys.exit(0)

			response = pack_message("ok", crypto_dictionary, GLOBAL_VERBOSE)
			if response[0]:
				try:
					socket.send(response[1])
				except Exception as inst:
					print "Error [ socket.send (message) ]: " + str(inst)
					# sys.exit(0)
			else:
				print response[1]
				# sys.exit(0)

	except Exception as inst:
		print "Error [ MAIN LOOP -> UNKNOWN ORIGIN ]: " + str(inst)
		socket.send("-1")

