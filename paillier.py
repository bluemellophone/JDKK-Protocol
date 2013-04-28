import math
import random
from Crypto.PublicKey import RSA

class PAILLIER_Private(object):
	keydata = ['p', 'q', 'lambda', 'mu']

	def __init__(self, filename):
		keys = {}
		for line in open(filename):
			if "-" not in line:
				line = line.split(":")
				keys[line[0]] = long(line[1])

		self.p = keys["p"]
		self.q = keys["q"]
		self.lam = keys["lambda"]
		self.mu = keys["mu"]

	def __str__(self):
		return "<%s @0x%x %s>" % (self.__class__.__name__, id(self), ",".join(self.keydata))


class PAILLIER_Public(object):
	keydata = ['n', 'g']

	def __init__(self, filename):
		keys = {}
		for line in open(filename):
			if "-" not in line:
				line = line.split(":")
				keys[line[0]] = long(line[1])

		self.n = keys["n"]
		self.g = keys["g"]

	def __str__(self):
		attrs = []
		for k in self.keydata:
			if k == 'n':
				attrs.append("n(2048)")
			else:
				attrs.append(k)
		return "<%s @0x%x %s>" % (self.__class__.__name__, id(self), ",".join(attrs))

def pow_mod(x, y, z):
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number

def L(x, n1):
	return int( (x-1) / n1 )

def encrypt(m, pub):
	n1 = pub.n
	g1 = pub.g
	r = random.randint(1, n1 ** 2)
	return int((pow_mod(g1, m, (n1 ** 2)) * pow_mod(r, n1, (n1 ** 2))) % (n1 ** 2))

def decrypt(c, priv):
	n1 = priv.p * priv.q
	lam1 = priv.lam
	mu1 = priv.mu

	x = pow_mod(c, lam1, (n1 ** 2))
	lx = L(x, n1)
	return (lx * mu1) % n1

def add(c1, c2, N):
	# total = add(total, encrypted_ballots[i], N)
	return (c1 * c2) % (N ** 2)

def tally(cand, total):
	cand = (sorted(cand))[::-1]

	retVal = {}
	for c in cand:
		retVal[c] = 0

	mark = 0
	while total > 0 and mark < len(cand):
		if total - cand[mark] >= 0:
			retVal[cand[mark]] += 1
			total -= cand[mark]
		else:
			mark += 1

	return retVal
