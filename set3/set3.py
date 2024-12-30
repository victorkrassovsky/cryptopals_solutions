import cbc
import os
import base64 as b64
import random

# provides a random ciphertext encrypted with a random key
def encryption_oracle():
    key = b'{\xf2ieB\xd7v)^\x98m|F\x89\\\x82'
    with open('c17.txt', 'r') as f:
        lines = [b64.b64decode(l.strip()) for l in f]
    pt = lines[random.randint(0,len(lines))]
    ct = cbc.cbc_encrypt(pt, key)
    return ct
