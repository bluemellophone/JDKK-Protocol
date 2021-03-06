import sys
import getpass
import zmq
import util
import inspect
import sha
import paillier
import rsa
import base64
from Crypto.PublicKey import RSA

def encodeMessage(message):
	message = str(message)

	message = message.replace(".", "^__PERIOD__^")
	message = message.replace(",", "^__COMMA__^")
	message = message.replace(";", "^__SEMICOLON__^")
	message = message.replace("|", "^__PIPE__^")
	return message

def verifyCloseConnection(crypto_dict, message):
	try:
		decode = base64.b64decode(message)
		key = crypto_dict["rsa_server_public_key"][crypto_dict["rsa_user_public_key_hash"]][0]
		return [True, rsa.unsign(key, decode)]
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: " + str(inst)]

def print_candidates(crypto_dict):
	cand = crypto_dict["candidates"]

	print "\n-------------------------------------------------------------------------------- \n"
	print "Candidates:"
	for key in sorted(cand.keys()):
		print "   " + str(key) + " - " + str(cand[key][1])

	print "\n-------------------------------------------------------------------------------- \n"

####################################################
############### Handshake Functions ################
####################################################

def pack_handshake(message, crypto_dict, verbose = False):
	
	if verbose:
		print "\n"

	# Compile message
	client_message = encodeMessage(message) + ";" + crypto_dict["rsa_user_public_key_hash"]

	return util.pack_handshake_general(client_message, crypto_dict, "client", verbose)

def unpack_handshake(encoded_message, crypto_dict, verbose = False):
	
	if verbose:
		print "\n"
		
	if "." in encoded_message:
		encoded_message = encoded_message[1:]
		vcc = verifyCloseConnection(crypto_dict, encoded_message)
		if vcc[0]:
			if vcc[1] == "close":
				return [False, "Error: connection closed by server"]
			else:
				return [False, "Error: connection closed for an unknown reason, possibly malicious"]
		return vcc

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
		
	if "." in encoded_message:
		encoded_message = encoded_message[1:]
		vcc = verifyCloseConnection(crypto_dict, encoded_message)
		if vcc[0]:
			if vcc[1] == "close":
				return [False, "Error: connection closed by server"]
			else:
				return [False, "Error: connection closed for an unknown reason, possibly malicious"]
		return vcc
		
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

c = 1
registered_voters_public_keys = {}
while True:
	temp_filename = "keys/public/voter" + str(c) + ".public"
	try:
	   with open(temp_filename ): pass
	except IOError:
	   break

	c += 1
c -= 1

voter_id = -1
while voter_id < 1 or voter_id > c:
	voter_id = int(raw_input("What is your voter number (1 - " + str(c) + ")? "))


temp = RSA.importKey(open("keys/public/voter" + str(voter_id) + ".public", "r").read())
temp_hash = sha.sha256(str(temp.n))

crypto_dictionary = {
	"client_nonces" : { temp_hash : False } ,
	"server_nonces" : { temp_hash : "0" } , # Default Server Nonce to begin with
	"rsa_user_public_keys" : { temp_hash: [ temp, False ] } ,
	"rsa_user_private_key" : RSA.importKey(open("keys/private/voter" + str(voter_id) + ".private", "r").read()) ,
	"rsa_server_public_key" : { temp_hash : [ RSA.importKey(open("keys/public/server.public", "r").read()), False ] } ,
	"homomorphic_public_key" : paillier.PAILLIER_Public("keys/public/homomorphic.public"),
	"aes_session_keys" : { temp_hash : False },
	"client_aes_id" : False ,
	"rsa_user_public_key_hash" : temp_hash ,
	"candidates": False
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
	if GLOBAL_VERBOSE:
		print "Received Handshake:", response[1]

	message = response[1].split(";")
	print "Handshake Response:", message[0]
	crypto_dictionary["aes_session_keys"][crypto_dictionary["rsa_user_public_key_hash"]] = message[1]
	crypto_dictionary["client_aes_id"] = message[2]
	candidate_string = message[3]
	
	candidates = {}
	counter = 1
	for candidate in candidate_string.split("-"):
		if ":" in candidate:
			candidate = candidate.split(":")
			candidates[counter] = (int(candidate[0]), candidate[1])
			counter += 1

	crypto_dictionary["candidates"] = candidates

	if GLOBAL_VERBOSE:
		print "Updated AES Session Key:", crypto_dictionary["aes_session_keys"][crypto_dictionary["rsa_user_public_key_hash"]]
		print "Updated AES Session ID:", crypto_dictionary["client_aes_id"]
		print "Updated Candidates Dictionary", crypto_dictionary["candidates"]
else:
	print response[1]
	sys.exit(0)

################## Messages ####################

status = 0
while status != "ok":	
	vote_original = 0
	vote_verification = 0
	while vote_original != vote_verification or (vote_original == 0 and vote_verification == 0):
		print_candidates(crypto_dictionary)

		if vote_original != vote_verification:
			print "Vote Verification Failed!\n"

		print "Vote for your candidate by inputting their corresponding number..."

		vote_original = int(raw_input("Vote: "))
		while vote_original not in range(1, len(crypto_dictionary["candidates"]) + 1):
			print "Invalid Vote!\n"
			vote_original = int(raw_input("Vote: "))
		
		print "You have selected to vote for:", crypto_dictionary["candidates"][vote_original][1]
		vote_verification = int(raw_input("Vote Verification: "))
		while vote_verification not in range(1, len(crypto_dictionary["candidates"]) + 1):
			print "Invalid Vote!\n"
			vote_verification = int(raw_input("Vote Verification: "))

	print " "

	message = pack_message(paillier.encrypt(crypto_dictionary["candidates"][vote_original][0], crypto_dictionary["homomorphic_public_key"]), crypto_dictionary, GLOBAL_VERBOSE)
	if message[0]:
		try:
			util.debug(GLOBAL_VERBOSE, "client_aes_id", crypto_dictionary["client_aes_id"])
			socket.send(crypto_dictionary["client_aes_id"] + "." + message[1])
		except Exception as inst:
			print "Error [ socket.send (message) ]: " + str(inst)
			sys.exit(0)
	else:
		print "--------------------------------------------------------------------------------\n"
		print message[1]
		print " "
		sys.exit(0)

	response = unpack_message(socket.recv(), crypto_dictionary, GLOBAL_VERBOSE)
	if response[0]:
		if GLOBAL_VERBOSE:
			print "Received Message:", response[1]

		message = response[1].split(";")
		status = message[0]
		crypto_dictionary["client_aes_id"] = message[1]

		if GLOBAL_VERBOSE:
			print "Updated AES Session ID:", crypto_dictionary["client_aes_id"]
	else:
		print "--------------------------------------------------------------------------------\n"
		print response[1]
		print " "
		sys.exit(0)

print "--------------------------------------------------------------------------------\n"
print "Thank you for voting, Goodbye! "
print " "

