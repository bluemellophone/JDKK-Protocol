from Crypto.Hash import SHA256

# pretty basic wrapper
def sha256(input):
    temp = SHA256().new()
    temp.update(input)
    return temp.hexdigest()

# what other things would be useful here...
# append hash to input, delimit with ','
def append_sha256(input):
    return (input + sha256(input))
