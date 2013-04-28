import paillier
import sys
import util
from Crypto.PublicKey import RSA
import sha

GLOBAL_VERBOSE = "-v" in sys.argv
if GLOBAL_VERBOSE:
	sys.argv.remove("-v")


candidates_list = ["A. Baker", "C. Dwight", "E. Fredricks", "G. Hayes", "I. Jackson", "K. Lowe", "M. Newman", "O. Parker", "Q. Revas", "S. Taylor", "U. Victor", "W. Xi", "Y. Zetterburg"] # Names supplied by my wife

# Open public keys
c = 1
registered_voters_public_keys = {}
while True:
	temp_filename = "keys/public/voter" + str(c) + ".public"
	try:
	   with open(temp_filename ): pass
	except IOError:
	   break

	temp_key = RSA.importKey(open(temp_filename , "r").read())
	temp_hash = sha.sha256(str(temp_key.n))
	registered_voters_public_keys[temp_hash] = temp_key
	c += 1

if GLOBAL_VERBOSE: 
	print "RSA Public Key Hash Dictionary:"
	print registered_voters_public_keys
	print "\n\n"

candidates = {}
Base = util.ballot_base(len(registered_voters_public_keys))
for i in range(len(candidates_list)):
	candidates[int(2 ** (Base * i))] = candidates_list[i]


private_key = paillier.PAILLIER_Private("keys/private/homomorphic.private")

d = paillier.decrypt(long(open("votes.txt" , "r").read()), private_key)
print "Ballot Decrypted:", d

result = paillier.tally(candidates.keys(), d)
winners = []
win = max(result.values())
for key in sorted(result.keys()):
	for k in candidates.keys():
		if key == k:
			if result[key] == win:
				winners.append(candidates[k])
			print "Candidate", candidates[k], "has", result[key], "votes"
			break
print winners

print " "
if len(winners) > 1:
	print "There is a tie between", len(winners), "candidates:"
	for winner in winners:
		print "   Candidate", winner
elif len(winners) == 1:
	print "The winner of the election is Candidate", winners[0]
else:
	print "Election error."