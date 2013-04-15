from Crypto.PublicKey import RSA

keys = ["server", "client"]

for key in keys:
	temp = RSA.generate(2048)
	f = open("keys/" + str(key) + ".private", "w")
	f.write(temp.exportKey("PEM"))
	
	f.close()

	f = open("keys/" + str(key) + ".public", "w")
	f.write(temp.publickey().exportKey("PEM"))

	f.close()
