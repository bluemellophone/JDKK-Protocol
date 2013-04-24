import sys
import zmq
import util
import inspect
import rand
from Crypto.PublicKey import RSA

####################################################
############### Handshake Functions ################
####################################################

def pack_handshake(message, crypto_dict, verbose = False):
   	
	# Update AES session key
	try:
		crypto_dict["aes_session_key"] = str(rand.rand_byte(32))[:32]
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rand ]: " + str(inst)]

	util.debug(verbose, "aes_session_key", crypto_dict["aes_session_key"])

	# Compile message
	server_message = message + ";" + crypto_dict["aes_session_key"]

	return util.pack_handshake_general(server_message, crypto_dict, "server", verbose)

def unpack_handshake(encoded_message, crypto_dict, verbose = False):
	
	return util.unpack_handshake_general(encoded_message, crypto_dict, "server", verbose)

####################################################
############### Message Functions ##################
####################################################

def pack_message(message, crypto_dict, verbose = False):
	
	server_message = message

	return util.pack_message_general(server_message, crypto_dict, "server", verbose)

def unpack_message(encoded_message, crypto_dict, verbose = False):
	
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
registered_voters_public_keys = []
while True:
	temp_filename = "keys/public/voter" + str(c) + ".public"
	try:
	   with open(temp_filename ): pass
	except IOError:
	   break

	registered_voters_public_keys.append( RSA.importKey(open(temp_filename , "r").read()) )
	c += 1

print registered_voters_public_keys

crypto_dictionary = {
	"client_nonce" : False ,
	"server_nonce" :False ,
	"rsa_user_public_key" : False ,
	"rsa_server_private_key" : False ,
	"aes_session_key" : False
}

# Temporary
crypto_dictionary["rsa_user_public_key"] = RSA.importKey(open("keys/public/voter1.public", "r").read())
crypto_dictionary["rsa_server_private_key"] = RSA.importKey(open("keys/private/server.private", "r").read())

################## Handshake ####################

handshake = unpack_handshake(socket.recv(), crypto_dictionary, GLOBAL_VERBOSE)
if handshake[0]:
	print "Handshake Received:", handshake[1]
else:
	print handshake[1]
	socket.send("-1")
	sys.exit(0)

response = pack_handshake("handshake", crypto_dictionary, GLOBAL_VERBOSE)
if response[0]:
	try:
		socket.send(response[1])
	except Exception as inst:
		print "Error [ socket.send (handshake) ]: " + str(inst)
		sys.exit(0)
else:
	print response[1]
	sys.exit(0)


################## Messages ####################

while True:
	message = unpack_message(socket.recv(), crypto_dictionary, GLOBAL_VERBOSE)
	if message[0]:
		print "Message Received:", message[1]
	else:
		print message[1]
		socket.send("-1")
		sys.exit(0)

	response = pack_message("ok", crypto_dictionary, GLOBAL_VERBOSE)
	if response[0]:
		try:
			socket.send(response[1])
		except Exception as inst:
			print "Error [ socket.send (message) ]: " + str(inst)
			sys.exit(0)
	else:
		print response[1]
		sys.exit(0)

