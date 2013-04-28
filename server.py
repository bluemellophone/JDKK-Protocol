import sys
import zmq
import util
import inspect
import rand
import sha
import paillier
from Crypto.PublicKey import RSA

def decodeMessage(message):
	message = message.replace("^__PERIOD__^", ".")
	message = message.replace("^__COMMA__^", ",")
	message = message.replace("^__SEMICOLON__^", ";")
	message = message.replace("^__PIPE__^", "|")
	return message

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


candidates_list = ["A. Baker", "C. Dwight", "E. Fredricks", "G. Hayes", "I. Jackson", "K. Lowe", "M. Newman", "O. Parker", "Q. Revas", "S. Taylor", "U. Victor", "W. Xi", "Y. Zetterburg"] # Names supplied by my wife


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

candidates = {}
Base = util.ballot_base(len(registered_voters_public_keys))
for i in range(len(candidates_list)):
	candidates[int(2 ** (Base * i))] = candidates_list[i]

if GLOBAL_VERBOSE: 
	print "Candidates Dictionary:"
	print candidates
	print "\n\n"

crypto_dictionary = {
	"client_nonces" : {} ,
	"server_nonces" : {} ,
	"rsa_user_public_keys" : registered_voters_public_keys ,
	"rsa_server_private_key" : RSA.importKey(open("keys/private/server.private", "r").read()) ,
	"homomorphic_private_key" : paillier.PAILLIER_Private("keys/private/homomorphic.private") , 
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
				print "Handshake Received:", decodeMessage(message[0])

				if GLOBAL_VERBOSE:
					print "User Public Key Hash:", message[1]

			else:
				print handshake[1]

				try:	
					socket.send("-1")
				except Exception as inst:
					print "Error [ MAIN LOOP -> Server Connection Closure ]: " + str(inst)
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
				msg = decodeMessage(message[0])
				print "Message Received:", msg

				d = paillier.decrypt(long(msg), crypto_dictionary["homomorphic_private_key"])
				print "Ballot Decrypted:", d

				result = paillier.tally(crypto_dictionary["candidates"].keys(), d)
				winners = []
				win = max(result.values())
				for key in sorted(result.keys()):
					for k in crypto_dictionary["candidates"].keys():
						if key == k:
							if result[key] == win:
								winners.append(crypto_dictionary["candidates"][k])
							print "Candidate", crypto_dictionary["candidates"][k], "has", result[key], "votes"
							break
				print winners

				print " "
				if len(winners) > 1:
					print "There is a tie between", len(winners), "candidates:"
					for winner in winners:
						print "   Candidate", winner
				elif len(winners) == 1:
					print "The winner of the election is Candidate", winners[0]
				else:
					print "Election error."

				if GLOBAL_VERBOSE:
					print "User Public Key Hash:", message[1]
			else:
				print message[1]

				try:	
					socket.send("-1")
				except Exception as inst:
					print "Error [ MAIN LOOP -> Server Connection Closure ]: " + str(inst)

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

		try:	
			socket.send("-1")
		except Exception as inst:
			print "Error [ MAIN LOOP -> UNKNOWN ORIGIN -> Server Connection Closure ]: " + str(inst)

