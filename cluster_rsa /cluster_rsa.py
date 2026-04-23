from Crypto.Util.number import inverse, long_to_bytes

n = 8749002899132047699790752490331099938058737706735201354674975134719667510377522805717156720453193651
e = 65537
ct = 7011348546698474112161490342087439373442001416519454882503540905172500668976294922971434862617147484

# Replace these with the actual prime factors you got from FactorDB
primes = [
    9671406556917033397931773,
    9671406556917033398314601,
    9671406556917033398439721,
    9671406556917033398454847
]

# 1. Calculate Euler's Totient function for Multi-Prime RSA
phi = 1
for p in primes:
    phi *= (p - 1)

# 2. Calculate the Private Key (d)
d = inverse(e, phi)

# 3. Decrypt the Ciphertext
m = pow(ct, d, n)

# 4. Convert the Integer to readable text (bytes)
flag = long_to_bytes(m)
print("Decrypted Flag:", flag.decode())