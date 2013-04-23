from Crypto import Random

#Create a nonce with a length of "setlength" bytes
#Defaults to size of 8 bytes (64 bit)
def nonce_byte(setlength=None):
	if setlength is None:
		setlength = 8
	return Random.get_random_bytes(setlength)
	
#Return a pseudo-random number of "setlength" bytes
#Defaults to size of 8 bytes
#Converts python module output to little-endian number
def rand_byte(setlength=None):
	if setlength is None:
		setlength = 8
	val = Random.get_random_bytes(setlength)
	temp = sum(ord(val[i]) << (i * 8) for i in range(len(val)))
	return temp
	
'''
#Create a nonce with a length of "setlength" bits
#Defaults to size of 64 bits
def nonce_bit(setlength=None):
	if setlength is None:
		setlength = 64
	if (setlength%8) != 0:
		val = (ord(b) for b in Random.get_random_bytes(1))
		for b in val:
			for i in xrange(setlength%8):
				temp = temp + (((b >> i) & 1) * (2**(i-1)))
		setlength = setlength - (setlength%8)
	val = (ord(b) for b in Random.get_random_bytes(setlength/8))
	j = 0
		for b in val:
			for i in xrange(8):
				temp = temp + (((b >> i) & 1) * (2**((i-1)+(j*8))))
			j = j + 1
	return temp

#Create a nonce with a length of "setlength" bits
#Defaults to size of 64 bits
def rand_bit(setlength=None):
	if setlength is None:
		setlength = 64
	temp = 0
	if (setlength%8) != 0:
		val = (ord(b) for b in Random.get_random_bytes(1))
		for b in val:
			for i in xrange(setlength%8):
				temp = temp + (((b >> i) & 1) * (2**(i-1)))
		setlengths = setlength - (setlength%8)
	val = (ord(b) for b in Random.get_random_bytes(setlength/8))
	j = 0
	for b in val:
		for i in xrange(8):
			temp = temp + (((b >> i) & 1) * (2**((i-1)+(j*8))))
		j = j + 1
	return temp
	
'''