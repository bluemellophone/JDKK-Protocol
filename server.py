import sys
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
	socket = context.socket(zmq.REP)
	socket_host = "127.0.0.1"
	socket_port = sys.argv[1]
	socket.bind("tcp://"+socket_host+":"+socket_port)
except Exception as inst:
	print "Error: socket initialization (", inst, ")"
	sys.exit(0)

print "\
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

key = "1234567890123VB67890A23456789012"

while True:
	msg = socket.recv()
	msg = aes.aes_decrypt(key, msg)
	print msg
	msg = msg.strip(".")
	msg = msg.split(",")
	print msg

	msg = msg[0]
	print "Received Message:", msg
	socket.send(msg + " resp")
