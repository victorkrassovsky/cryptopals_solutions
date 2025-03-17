import cbc
import ctr
import os
import base64 as b64
import random
import time
import mt19937

# provides a random ciphertext encrypted with a random key
def ciphertext_generator():
    key = b'{\xf2ieB\xd7v)^\x98m|F\x89\\\x82'
    with open('c17.txt', 'r') as f:
        lines = [b64.b64decode(l.strip()) for l in f]
    pt = lines[random.randint(0,len(lines)-1)]
    ct = cbc.cbc_encrypt(pt, key)
    return ct

# accepts a byte file and attempts to decrypt it using cbc
# if the resulting plaintext has valid padding returns true
# otherwise returns false
def padding_oracle(byte_file):
    key = b'{\xf2ieB\xd7v)^\x98m|F\x89\\\x82'
    try:
        pt = cbc.cbc_decrypt(byte_file, key)
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
    # TAKES A FEW SECONDS
    for i in range(1, len(ct_blocks)):
        # we need to modify the i-1th ct block to recover ith block
        prev_block = ct_blocks[i-1]
        cur_block = ct_blocks[i]
        pt = bytearray(16)
        # first need to recover last byte of the block
        for j in range(0, 256):
            temp_block = xor_strings(prev_block, j.to_bytes(16,'big'))
            corrupt_block = xor_strings(temp_block, bytes(14) + b'\x01\x00')
            if padding_oracle(temp_block + cur_block) and padding_oracle(corrupt_block + cur_block):
                # now j xor pt has last byte \x01, hence last byte of pt is \x01 xor j
                pt[-1] = j ^ 1
                #print(pt[-1])
                break

        # recover the kth byte
        for k in range(2, 17):
            for j in range(0,256):
                temp_block = xor_strings(prev_block, bytes(16-k) + j.to_bytes(1,'big') +  bytes(pt[-(k-1):]))
                temp_block = xor_strings(temp_block, bytes(17-k)  + (k-1)*(k.to_bytes(1,'big')))
                if padding_oracle(temp_block + cur_block):
                    pt[-k] = j ^ k
                    break
        #print(pt)
        result += bytes(pt)
    return result

# tests ctr mode implmeented in ctr.py
def c18():
    ct_before_nonce = b64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    ct = bytes(16) + ct_before_nonce
    key = b'YELLOW SUBMARINE'
    pt = ctr.ctr_decrypt(ct, key, endian='little')
    return pt

# breaks fixed nonce ctr mode encrypted files found in c19.txt
# I phyiscally looked at each ciphertext and guessed each character using the parts of words
# that were currently known, so this is unfeasible for large texts
def c19():
    key = os.urandom(16)
    with open('c19.txt','r') as f:
        lines = [ctr.ctr_encrypt(b64.b64decode(l.strip()), key, nonce=bytes(8))[16:] for l in f]
        
    # we essentially just need to break many time pad
    longest = max(lines, key=len) # this line is tricky to decrypt fully
    pairwise_xored = [xor_strings(l, longest) for l in lines]

    result = b''
    # use big homosapian brain to guess each letter one at a time
    for i,l in enumerate(pairwise_xored):
        guess = b'He, too, has been changed in his turn,' # vary the guess to get each char
        pt = xor_strings(guess, l)
        result += pt + b' \n'
    return str(result, 'utf-8')

def score_single_character(c):
    alpha = b'abcdefghijklmnopqrstuvwxyz '
    alpha += alpha.upper()
    if c in good_chars:
        return 1
    return 0

def score_byte_file(byte_file):
    total = 0
    for c in byte_file:
        total += score_single_character(c)
    return total

def find_best(byte_file):
    best_score,best_i,best_s = -1,-1, b''
    for i in range(256):
        s = xor_strings(byte_file, i.to_bytes(1,'big') * len(byte_file))
        score = score_byte_file(s)
        if score > best_score:
            best_i,best_score,best_s = i,score,s
    return best_i
        
# breaks fixed nonce ctr mode encrypted files found in c20.txt
# now we use an automated method, it does not decrypt the entire text, but the large majority of it
def c20():
    key = os.urandom(16)
    with open('c20.txt', 'r') as f:
        lines = [ctr.ctr_encrypt(b64.b64decode(l.strip()),key, nonce=bytes(8))[16:] for l in f]
    
    shortest_length = len(min(lines, key=len))
    truncated = [l[:shortest_length] for l in lines]
    transposed = [bytes([truncated[j][i] for j in range(len(truncated))]) for i in range(len(truncated[0]))]
    solved = [find_best(l) for l in transposed]
    xor_key = bytes(solved)
    result = b''
    for l in lines:
        s = xor_strings(xor_key, l)
        print(s)
        result += s + b' \n'
    return result

# tests the prng found in mt19937.py
def c21():
    gen1 = mt19937.Mt19937(1)
    gen2 = mt19937.Mt19937(1)
    try:
        for i in range(100):
            assert(gen1.random_32bits() == gen2.random_32bits())
    except:
        print("Test failed")
    else:
        print("Tests succeeded")
    
# I am going to skip c22-24, since I don't think they are actually related to crypto
# (since the mersenne twister isn't even used in crypto at all)
# and I don't know how to test my mt19937 implementation
