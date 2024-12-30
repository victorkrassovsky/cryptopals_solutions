import cbc
import os
import base64 as b64
import random

# provides a random ciphertext encrypted with a random key
def ciphertext_generator():
    key = b'{\xf2ieB\xd7v)^\x98m|F\x89\\\x82'
    with open('c17.txt', 'r') as f:
        lines = [b64.b64decode(l.strip()) for l in f]
    pt = lines[random.randint(0,len(lines))]
    ct = cbc.cbc_encrypt(pt, key)
    return ct

# accepts a byte file and attempts to decrypt it using cbc
# if the resulting plaintext has valid padding returns true
# otherwise returns false
def padding_oracle(byte_file):
    key = b'{\xf2ieB\xd7v)^\x98m|F\x89\\\x82'
    try:
        cbc.cbc_decrypt(byte_file, key)
    except Exception:
        return False
    else:
        return True
        
# decrypts a ciphertext given by ciphertext_generator with access to padding_oracle        
def c17():
    # get ciphertext
    ct = ciphertext_generator()
    ct_blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    # recover each block
    for i in range(1, ct_blocks()):
        rest = b''.join(ct_blocks[0:i-1])
        # we need to modify the i-1th ct block to recover ith block
        prev_block = ct_blocks[i-1]
        cur_block = ct_blocks[i]
        
