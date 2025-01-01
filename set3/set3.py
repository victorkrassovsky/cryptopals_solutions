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
    except Exception as inst:
        (c,) = inst.args
        if c == 'Invalid padding':
            return False
        else:
            raise inst
    else:
        return True

# xors two byte strings of possibly different lengths
def xor_strings(a,b):
    if type(a) != type(b) or type(a) != bytes:
        raise Exception("Not bytes")
    if len(a) < len(b):
        return b''.join([(x^y).to_bytes(1,'big') for x,y in zip(a, b[:len(a)])])
    else:
        return b''.join([(x^y).to_bytes(1,'big') for x,y in zip(a[:len(b)], b)])

# decrypts a ciphertext given by ciphertext_generator with access to padding_oracle        
def c17():
    # get ciphertext
    ct = ciphertext_generator()
    ct_blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    result = b''
    # recover each block
    for i in range(1, len(ct_blocks)):
        print(i)
        # we need to modify the i-1th ct block to recover ith block
        prev_block = ct_blocks[i-1]
        cur_block = ct_blocks[i]
        pt = bytearray(16)
        # first need to recover last byte of the block
        for j in range(0, 256):
            temp_block = xor_strings(prev_block, j.to_bytes(16,'big'))
            corrupt_block = xor_strings(temp_block, bytes(14) + b'\x01\x00')
            if padding_oracle(temp_block + cur_block) and (not padding_oracle(corrupt_block + cur_block)):
                # now j xor pt has last byte \x01, hence last byte of pt is \x01 xor j
                pt[-1] = j ^ 1
                break

        # recover the kth byte
        for k in range(2, 17):
            for j in range(0,256):
                temp_block = xor_strings(prev_block, bytes(16-k) + j.to_bytes(1,'big') +  bytes(pt[-(k-1):]))
                temp_block = xor_strings(temp_block, bytes(17-k)  + (k-1)*(k.to_bytes(1,'big')))
                if padding_oracle(temp_block + cur_block):
                    pt[-k] = j
                    break
        print(pt)
        result += pt
    return result

#TODO: Fix whatever is broken
