import zmq
context = zmq.Context()
socket = context.socket(zmq.REQ)
socket.connect("tcp://127.0.0.1:50001")

for i in range(100):
    msg = raw_input("Message:")
    socket.send(msg)
    print "Sending", msg
    msg_in = socket.recv()
    print msg_in