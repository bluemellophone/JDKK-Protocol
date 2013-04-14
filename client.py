import sys
import getpass
import zmq # networking library
import aes
import rsa
import sha
import rand

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

print "\
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

# email = getpass.getpass("RCS ID:")
# password = getpass.getpass("SIS Password:")

email = "parhaj@rpi.edu"
password = "TemPa$$w0rd"

if len(email) > 32:
	email = email[:32]

if len(password) > 32:
	password = password[:32]

# Handshake
key = "1234567890123VB67890A23456789012"

# Cast Ballot
# msg = raw_input("Message: ")  
msg = "This is an example message!"  
msg = msg + "," + email + "," + password

while len(msg) % 16 != 0:
	msg = msg + "."

print msg, len(msg)
e_msg = aes.aes_encrypt(key, msg)

socket.send(e_msg)

msg = socket.recv()
print "Response:", msg
