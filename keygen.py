from Crypto.PublicKey import RSA

num_voters = 10

keys = ["server"]
for i in range(10):
	keys.append("voter" + str(i + 1))

for key in keys:
	print "Generating keys for:", key
	temp = RSA.generate(2048)
	f = open("keys/private/" + str(key) + ".private", "w")
	f.write(temp.exportKey("PEM"))
	
	f.close()

	f = open("keys/public/" + str(key) + ".public", "w")
	f.write(temp.publickey().exportKey("PEM"))

	f.close()
