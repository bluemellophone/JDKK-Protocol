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
	n1 = pub[0]
	g1 = pub[1]
	r = random.randint(1, n1 ** 2)
	return int((pow_mod(g1, m, (n1 ** 2)) * pow_mod(r, n1, (n1 ** 2))) % (n1 ** 2))

def decrypt(c, priv):
	n1 = priv[0] * priv[1]
	lam1 = priv[2]
	mu1 = priv[3]

	x = pow_mod(c, lam1, (n1 ** 2))
	lx = L(x, n1)
	return (lx * mu1) % n1

def add(c1, c2, N):
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



if __name__ == "__main__":

	pri_key = PAILLIER_Private("keys/private/homomorphic.private")
	pub_key = PAILLIER_Public("keys/public/homomorphic.public")
	
	p = pri_key.p
	q = pri_key.q
	N = pub_key.n
	lam = pri_key.lam
	g = pub_key.g
	mu = pri_key.mu

	public_key = (N, g)
	private_key = (p, q, lam, mu)

	print "\n"

	# Number of Registered Voters
	V = 10
	# Number of Candidates
	C = 8

	Base = int(math.ceil(math.log(V, 2))) + 1
	print "Each candidate needs", Base, "bits to be represented (", (2 ** Base), ")"
	print "Each ballot needs", Base * C, "bits to be represented"
	print " "

	########################################################

	candidates = {}
	for i in range(C):
		candidates[i] = int(2 ** (Base * i))

	print "Candidate IDs:"
	for key in candidates:
		print "   Candidate", (key + 1), "ID:", candidates[key]

	########################################################

	votes = {}
	print " "
	ballots = []
	for i in range(V):
		# ballots.append(candidates[i % len(candidates)])
		vote = random.randint(0, len(candidates) - 1)

		if vote in votes:
			votes[vote] += 1
		else:
			votes[vote] = 1

		ballots.append(candidates[vote])
		
	# print "Voter Ballots:"
	# for i in range(len(ballots)):
	# 	print "   Voter", (i + 1), "Ballot:", str(ballots[i]).ljust(3, " ")

	########################################################

	print " "
	encrypted_ballots = []
	for i in range(len(ballots)):
		encrypted_ballots.append(encrypt(ballots[i], public_key))

	# print "Encrypted Voter Ballots:"
	# for i in range(len(encrypted_ballots)):
		# print "   Encrypted Voter", (i + 1), "Ballot:", encrypted_ballots[i]
		# print len(str(encrypted_ballots[i]))

	########################################################

	print " "
	total = encrypted_ballots[0]
	for i in range(1, len(encrypted_ballots)):
		total = add(total, encrypted_ballots[i], N)

	print "Encrypted Ballot Total:", total
	d = decrypt(total, private_key)
	print "Decrypted Ballot Total:", d

	########################################################

	print " "
	print "Vote Results Correct:"
	for key in votes:
		print "Candidate", (key + 1), "has", votes[key], "votes"
	print " "
	print "Vote Results:"
	result = tally(candidates.values(), d)
	winners = []
	win = max(result.values())
	for key in sorted(result.keys()):
		for k in candidates:
			if key == candidates[k]:
				if result[key] == win:
					winners.append(k + 1)
				print "Candidate", (k + 1), "has", result[key], "votes"

	print " "
	if len(winners) > 1:
		print "There is a tie between", len(winners), "candidates:"
		for winner in winners:
			print "   Candidate", winner
	elif len(winners) == 1:
		print "The winner of the election is Candidate", winners[0]
	else:
		print "Election error."
