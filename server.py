import sys
import zmq
import util
import inspect
import rand
import sha
import paillier
import base64
import rsa
from Crypto.PublicKey import RSA

def decodeMessage(message):
	message = message.replace("^__PERIOD__^", ".")
	message = message.replace("^__COMMA__^", ",")
	message = message.replace("^__SEMICOLON__^", ";")
	message = message.replace("^__PIPE__^", "|")
	return message

def closeConnection(crypto_dict, verbose):

	if verbose:
		print " "
		print util.debug_spacing + "Debug: Closing connection with client."

	try:
		close_message = "." + base64.b64encode(rsa.sign(crypto_dict["rsa_server_private_key"], "close"))
		util.debug(verbose, "close_message", close_message)
		return close_message
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + "]: " + str(inst)]


####################################################
############### Handshake Functions ################
####################################################

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
	server_message = message + ";" + crypto_dict["aes_session_keys"][crypto_dict["rsa_user_public_key_hash"]] + ";" + crypto_dict["aes_session_ids"][crypto_dict["rsa_user_public_key_hash"]]+ ";"

	for key in sorted(crypto_dict["candidates"].keys()):
		server_message += str(key) + ":" + str(crypto_dict["candidates"][key]) + "-"

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
################################################
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

open("public.txt" , "w").close()
open("votes.txt" , "w").close()

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
	registered_voters_public_keys[temp_hash] = [ temp_key, False ]
	c += 1

if GLOBAL_VERBOSE: 
	print "RSA Public Key Hash Dictionary:"
	print registered_voters_public_keys
	print "\n\n"

candidates = {}
Base = util.ballot_base(len(registered_voters_public_keys))
for i in range(len(util.candidates_list)):
	candidates[int(2 ** (Base * i))] = util.candidates_list[i]

if GLOBAL_VERBOSE: 
	print "Candidates Dictionary:"
	print candidates
	print "\n\n"

crypto_dictionary = {
	"client_nonces" : {} ,
	"server_nonces" : {} ,
	"rsa_user_public_keys" : registered_voters_public_keys ,
	"rsa_server_private_key" : RSA.importKey(open("keys/private/server.private", "r").read()) ,
	"aes_session_keys" : {} ,
	"aes_session_ids" : {} ,
	"rsa_user_public_key_hash" : False,
	"candidates": candidates
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
				print "Handshake Received:", message[1]
				print " "

				response = pack_handshake("handshake", crypto_dictionary, GLOBAL_VERBOSE)
				if response[0]:
					try:
						socket.send(response[1])
					except Exception as inst:
						print "Error [ socket.send (handshake) ]: " + str(inst)
						print " "
						# sys.exit(0)
				else:
					print response[1]
					# sys.exit(0)

			else:
				print handshake[1]

				try:	
					socket.send(closeConnection(crypto_dictionary, GLOBAL_VERBOSE))
				except Exception as inst:
					print "Error [ MAIN LOOP -> Server Connection Closure ]: " + str(inst)
				# sys.exit(0)

		else:
			################## Messages ####################

			message = unpack_message(received, crypto_dictionary, GLOBAL_VERBOSE)
			if message[0]:

				msg_public_key = message[1][0]
				msg_ballot = message[1][1]
				msg_signature = message[1][2]
				message = msg_ballot.split(";")
				msg = decodeMessage(message[0])
				msg_hash = message[1]

				crypto_dictionary["rsa_user_public_keys"][msg_hash][1] = True

				rec = str(msg_public_key) + " | " + str(msg) + " | " + str(msg_signature) + "\n"
				print "Received:", rec

				with open("public.txt", "a") as publictxt:
				    publictxt.write(rec)

				votestxttemp = open("votes.txt", "r")
				temp = votestxttemp.read()
				votestxttemp.close()

				votestxt = open("votes.txt", "w")
				if len(temp) == 0:
					votestxt.write(str(long(msg)))
				else:
					d = paillier.add(long(temp), long(msg), paillier.PAILLIER_Private("keys/private/homomorphic.private"))
					votestxt.write(str(d))
				votestxt.close()
				
				response = pack_message("ok", crypto_dictionary, GLOBAL_VERBOSE)
				if response[0]:
					try:
						socket.send(response[1])
					except Exception as inst:
						print " "
						print "Error [ socket.send (message) ]: " + str(inst)
						print " "
						# sys.exit(0)
				else:
					print response[1]
					# sys.exit(0)

			else:

				print message[1]
				print " "

				try:	
					socket.send(closeConnection(crypto_dictionary, GLOBAL_VERBOSE))
				except Exception as inst:
					print "Error [ MAIN LOOP -> Server Connection Closure ]: " + str(inst)

				# sys.exit(0)

	except Exception as inst:
		print "Error [ MAIN LOOP -> UNKNOWN ORIGIN ]: " + str(inst)

		try:	
			socket.send(closeConnection(crypto_dictionary, GLOBAL_VERBOSE))
		except Exception as inst:
			print "Error [ MAIN LOOP -> UNKNOWN ORIGIN -> Server Connection Closure ]: " + str(inst)

