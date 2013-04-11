import zmq
context = zmq.Context()
socket = context.socket(zmq.REP)
socket.bind("tcp://127.0.0.1:50001")

while True:
    msg = socket.recv()
    print "Got", msg
    socket.send(msg)