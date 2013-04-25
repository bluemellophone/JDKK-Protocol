import math
import inspect
import aes
import rsa
import sha
import rand
import base64

debug_spacing = "   "
padding_length = 512

def ballot_base(num_regsitered_voters):
	return int(math.ceil(math.log(num_regsitered_voters,2)))

def ballot_length(num_regsitered_voters, num_candidates):
	return int(num_candidates) * ballot_base(num_regsitered_voters)

# Debug print out
def debug(verbose, var_name, var):
	try:
		if verbose:
		    print debug_spacing + "Debug [ " + str(inspect.stack()[1][3]) + " -> " +  str(var_name) + " ] (len:" + str(len(var)) + "): " + str(var)
	except Exception as inst:
		print "Error [ Debug -> " + str(inspect.stack()[1][3]) + " -> " +  str(var_name) + " ]: " + str(inst)











####################################################
############### Handshake Functions ################
####################################################

def pack_handshake_general(message, crypto_dict, machine, verbose = False):
	
	if machine == "client":
		updated_nonce = "client_nonces"
		required_rsa_sign_key = "rsa_user_private_key"
		required_rsa_encrypt_key = "rsa_server_public_key"
	else:
		updated_nonce = "server_nonces"
		required_rsa_sign_key = "rsa_server_private_key"
		required_rsa_encrypt_key = "rsa_user_public_keys"
	
	# Update nonce
	try:
		crypto_dict[updated_nonce][crypto_dict["rsa_user_public_key_hash"]] = str(rand.rand_byte(32))[:32]
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rand ]: " + str(inst)]

	debug(verbose, updated_nonce, crypto_dict[updated_nonce])

	# Compile message
	nonced_message = message + "," + crypto_dict["client_nonces"][crypto_dict["rsa_user_public_key_hash"]] + "," + crypto_dict["server_nonces"][crypto_dict["rsa_user_public_key_hash"]] + ","

	# Padding nonced_message to length of 128
	while len(nonced_message) < padding_length:
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
		message_signature = str(rsa.sign(crypto_dict[required_rsa_sign_key], message_hash))
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
			rsa_encrypted_messages.append(str(rsa.encrypt(crypto_dict[required_rsa_encrypt_key][crypto_dict["rsa_user_public_key_hash"]], signed_message[ (i * 256) : (i + 1) * 256 ])))

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
	
	if verbose:
		print "\n"
		
	return [True, encoded_message]











def unpack_handshake_general(encoded_message, crypto_dict, machine, verbose = False):

	if machine == "client":
		required_rsa_decrypt_key = "rsa_user_private_key"
		required_rsa_verify_key = "rsa_server_public_key"
	else:
		required_rsa_decrypt_key = "rsa_server_private_key"
		required_rsa_verify_key = "rsa_user_public_keys"

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
			rsa_decrypted_message += str(rsa.decrypt(crypto_dict[required_rsa_decrypt_key], decoded_message))
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rsa.decrypt ]: " + str(inst)]

	debug(verbose, "rsa_decrypted_message", rsa_decrypted_message)

	# Message Parsing
	try:
		rdmSplit = rsa_decrypted_message.split("|")
		message_content, message_hash, message_signature = rdmSplit[0], rdmSplit[1], rdmSplit[2]

		debug(verbose, "message_content", message_content)
		debug(verbose, "message_hash", message_hash)
		debug(verbose, "message_signature", message_signature)

		mcSplit = message_content.split(",")
		message, client_nonce, server_nonce = mcSplit[0], mcSplit[1], mcSplit[2]

		debug(verbose, "message", message)
		debug(verbose, "client_nonce", client_nonce)
		debug(verbose, "server_nonce", server_nonce)

		if machine != "client":
			temp = message.split(";")
			crypto_dict["rsa_user_public_key_hash"] = temp[1]
			debug(verbose, "rsa_user_public_key_hash", crypto_dict["rsa_user_public_key_hash"])

	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> Message Parsing ]: " + str(inst)]
	
	# Decode signature
	try:
		message_signature = base64.b64decode(message_signature)
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> base64.b64decode (signature) ]: " + str(inst)]

	# Verify Signature
	try:
		if str(rsa.unsign(crypto_dict[required_rsa_verify_key][crypto_dict["rsa_user_public_key_hash"]], message_signature)) != message_hash:
			return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: signature verification failed"]
		elif verbose:
			print debug_spacing + "Debug [ " + str(inspect.stack()[0][3]) + " ]: signature verification passed"	
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rsa.unsign (Signature Verification) ]: " + str(inst)]

	# Verify Hash
	try:
		if str(sha.sha256(message_content)) != message_hash:
			return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: hash verification failed"]
		elif verbose:
			print debug_spacing + "Debug [ " + str(inspect.stack()[0][3]) + " ]: hash verification passed"
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> sha.sha256 (Hash Verification) ]: " + str(inst)]

	# Verify Nonce
	if machine == "client":
		if client_nonce != crypto_dict["client_nonces"][crypto_dict["rsa_user_public_key_hash"]]:
			return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: nonce verification failed"]
		elif verbose:
			print debug_spacing + "Debug [ " + str(inspect.stack()[0][3]) + " ]: nonce verification passed"	

		# Upadte crypto_dictionary
		crypto_dict["server_nonces"][crypto_dict["rsa_user_public_key_hash"]] = server_nonce
	else:
		# Upadte crypto_dictionary
		crypto_dict["client_nonces"][crypto_dict["rsa_user_public_key_hash"]] = client_nonce

	if verbose:
		print "\n"
		
	return [True, message]












####################################################
############### Message Functions ##################
####################################################

def pack_message_general(message, crypto_dict, machine, verbose = False):

	if machine == "client":
		updated_nonce = "client_nonces"
		required_rsa_key = "rsa_user_private_key"
	else:
		updated_nonce = "server_nonces"
		required_rsa_key = "rsa_server_private_key"
	
	# Update machine's nonce
	try:
		crypto_dict[updated_nonce][crypto_dict["rsa_user_public_key_hash"]] = str(rand.rand_byte(32))[:32]
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rand ]: " + str(inst)]

	debug(verbose, updated_nonce, crypto_dict[updated_nonce][crypto_dict["rsa_user_public_key_hash"]])

	# Compile message
	nonced_message = message + "," + crypto_dict["client_nonces"][crypto_dict["rsa_user_public_key_hash"]] + "," + crypto_dict["server_nonces"][crypto_dict["rsa_user_public_key_hash"]] + ","

	# Padding nonced_message to length of 128
	while len(nonced_message) < padding_length:
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
		message_signature = str(rsa.sign(crypto_dict[required_rsa_key], message_hash))
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
		key = crypto_dict["aes_session_keys"][crypto_dict["rsa_user_public_key_hash"]]
		debug(verbose, "key", key)
		aes_encrypted_message = str(aes.aes_encrypt(key, signed_message))
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> aes.aes_encrypt ]: " + str(inst)]

	# Encode message
	try:
		encoded_message = base64.b64encode(aes_encrypted_message)
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> base64.b64encode (encrypt) ]: " + str(inst)]

	debug(verbose, "encoded_message", encoded_message)

	if verbose:
		print "\n"
		
	return [True, encoded_message]











def unpack_message_general(encoded_message, crypto_dict, machine, verbose = False):
	
	if machine == "client":
		verify_nonce = "client_nonces"
		updated_nonce = "server_nonces"
		required_rsa_key = "rsa_server_public_key"
	else:
		verify_nonce = "server_nonces"
		updated_nonce = "client_nonces"
		required_rsa_key = "rsa_user_public_keys"
	
	debug(verbose, "encoded_message", encoded_message)
	
	if machine != "client":
		# Strip User ID
		encoded_message = encoded_message.split(".")
		user_id = encoded_message[0]
		encoded_message = encoded_message[1]

		debug(verbose, "aes_session_id", user_id)

	# Decode message
	try:
		decoded_message = base64.b64decode(encoded_message)
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> base64.b64decode (encrypt) ]: " + str(inst)]

	if machine != "client":
		crypto_dict["rsa_user_public_key_hash"] = None
		for key in crypto_dict["aes_session_ids"]:
			value = crypto_dict["aes_session_ids"][key]
			if value == user_id:
				crypto_dict["rsa_user_public_key_hash"] = key
				break

		if crypto_dict["rsa_user_public_key_hash"] == None:
			return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: User ID invalid"]

	# Decrypt message
	try:
		key = crypto_dict["aes_session_keys"][crypto_dict["rsa_user_public_key_hash"]]
		debug(verbose, "key", key)
		aes_decrypted_message = str(aes.aes_decrypt(key, decoded_message))
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> aes.decrypt ]: " + str(inst)]

	debug(verbose, "aes_decrypted_message", aes_decrypted_message)

	# Message Parsing
	try:
		rdmSplit = aes_decrypted_message.split("|")
		message_content, message_hash, message_signature = rdmSplit[0], rdmSplit[1], rdmSplit[2]

		# Remove any AES padding from signature
		message_signature = message_signature.strip(".")

		debug(verbose, "message_content", message_content)
		debug(verbose, "message_hash", message_hash)
		debug(verbose, "message_signature", message_signature)

		mcSplit = message_content.split(",")
		message, client_nonce, server_nonce = mcSplit[0], mcSplit[1], mcSplit[2]

		debug(verbose, "message", message)
		debug(verbose, "client_nonce", client_nonce)
		debug(verbose, "server_nonce", server_nonce)

		if machine != "client":
			temp = message.split(";")
			temp = temp[1]
			crypto_dict["rsa_user_public_key"] = crypto_dict["rsa_user_public_keys"][temp]

	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> Message Parsing ]: " + str(inst)]

	# Decode signature
	try:
		message_signature = base64.b64decode(message_signature)
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> base64.b64decode (signature) ]: " + str(inst)]

	# Verify Signature
	try:
		if str(rsa.unsign(crypto_dict[required_rsa_key][crypto_dict["rsa_user_public_key_hash"]], message_signature)) != message_hash:
			return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: signature verification failed"]
		elif verbose:
			print debug_spacing + "Debug [ " + str(inspect.stack()[0][3]) + " ]: signature verification passed"
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> rsa.unsign (Signature Verification) ]: " + str(inst)]

	# Verify Hash
	try:
		if str(sha.sha256(message_content)) != message_hash:
			return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: hash verification failed"]
		elif verbose:
			print debug_spacing + "Debug [ " + str(inspect.stack()[0][3]) + " ]: hash verification passed"
	except Exception as inst:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " -> sha.sha256 (Hash Verification) ]: " + str(inst)]

	# Verify Nonce
	if machine == "client":
		nonce = client_nonce
		nonce_updated = server_nonce
	else:
		nonce = server_nonce
		nonce_updated = client_nonce

	if nonce != crypto_dict[verify_nonce][crypto_dict["rsa_user_public_key_hash"]]:
		return [False, "Error [ " + str(inspect.stack()[0][3]) + " ]: nonce verification failed"]
	elif verbose:
		print debug_spacing + "Debug [ " + str(inspect.stack()[0][3]) + " ]: nonce verification passed"	

	# Upadte crypto_dictionary
	crypto_dict[updated_nonce][crypto_dict["rsa_user_public_key_hash"]] = nonce_updated

	if verbose:
		print "\n"
		
	return [True, message]

