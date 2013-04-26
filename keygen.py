from Crypto.PublicKey import RSA
import random

def gcd(a, b):
    while b:      
        a, b = b, a % b
    return a

def lcm(a, b):
    return a * b // gcd(a, b)

def multiplicativeInverse(x, modulus):
    if modulus <= 0:
       return False

    a = abs(x)
    b = modulus
    sign = -1 if x < 0 else 1

    c1 = 1
    d1 = 0
    c2 = 0
    d2 = 1

    while b > 0:
        q = a / b
        r = a % b

        c3 = c1 - q*c2
        d3 = d1 - q*d2

        c1 = c2
        d1 = d2
        c2 = c3
        d2 = d3
        a = b
        b = r

    if a != 1:
        False

    return c1 * sign

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

num_voters = 10

# RSA KEYS
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

# PAILLIER KEYS
print "Generating keys for: homomorphic"
temp = RSA.generate(2048) # piggiback p and q for Paillier from an RSA key
p = temp.p
q = temp.q
N = p * q
lam = lcm(p-1, q-1)

mu = False
while not mu:
	g = random.randint(1, N ** 2)
	a = pow_mod(g, lam, N ** 2)
	mu = multiplicativeInverse(L(a % (N ** 2), N), N)

f = open("keys/private/homomorphic.private", "w")
content = "-----BEGIN PAILLIER PRIVATE KEY-----" + "\n"
content += "p:" + str(p) + "\n"
content += "q:" + str(q) + "\n"
content += "lambda:" + str(lam) + "\n"
content += "mu:" + str(mu) + "\n"
content += "-----END PAILLIER PRIVATE KEY-----"
f.write(content)

f = open("keys/public/homomorphic.public", "w")
content = "-----BEGIN PAILLIER PUBLIC KEY-----" + "\n"
content += "n:" + str(N) + "\n"
content += "g:" + str(g) + "\n"
content += "-----END PAILLIER PUBLIC KEY-----"
f.write(content)
