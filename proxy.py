import sys
import zmq # networking library

####################################################
################### Init Errors ####################
####################################################

if (len(sys.argv) != 3):
	print "Usage: python proxy.py client_port server_port"
	sys.exit(0)

if (sys.argv[1] == sys.argv[2]):
	print "Error: client_port and server_port are the same"
	sys.exit(0)

if (int(sys.argv[1]) not in range(0, 65535)):
	print "Error: invalid client_port given"
	sys.exit(0)

if (int(sys.argv[2]) not in range(0, 65535)):
	print "Error: invalid server_port given"
	sys.exit(0)

####################################################
################## Socket Setup ####################
####################################################

socket_host = "127.0.0.1"

try:
	contextServer = zmq.Context()
	socketServer = contextServer.socket(zmq.REP)
	socketServer_port = sys.argv[1]
	socketServer.bind("tcp://"+socket_host+":"+socketServer_port)
except Exception as inst:
	print "Error: server socket initialization (", inst, ")"
	sys.exit(0)

try:
	contextClient = zmq.Context()
	socketClient = contextClient.socket(zmq.REQ)
	socketClient_port = sys.argv[2]
	socketClient.connect("tcp://"+socket_host+":"+socketClient_port)
except Exception as inst:
	print "Error: client socket initialization (", inst, ")"
	sys.exit(0)

print "\n\n\
--------------------------------------------------------------------------- \n\
|     _ ___  _  ___  __ __   __   _   _             ___                   | \n\
|  _ | |   \| |/ / |/ / \ \ / /__| |_(_)_ _  __ _  | _ \_ _ _____ ___  _  | \n\
| | || | |) | ' <| ' <   \ V / _ \  _| | ' \/ _` | |  _/ '_/ _ \ \ / || | | \n\
|  \__/|___/|_|\_\_|\_\   \_/\___/\__|_|_||_\__, | |_| |_| \___/_\_\\\_, | | \n\
|                                           |___/                   |__/  | \n\
--------------------------------------------------------------------------- \n\
"

####################################################
#################### Main Code #####################
####################################################

while True:
    msg = socketServer.recv()
    print "Forwarding to Server (len:" + str(len(msg)) + ")"
    socketClient.send(msg)
    
    msg = socketClient.recv()
    print "Forwarding to Client (len:" + str(len(msg)) + ")"
    socketServer.send(msg)
