import base64
import aes128 as aes
import cbc
import os
import random

# pads a byte file to a desired length using pkcs#7 
def pad_file(byte_file, blocklength=16):
    if blocklength > 255:
        raise Exception("Blocklength too large")
    if len(byte_file) % blocklength == 0:
        return byte_file + blocklength*blocklength.to_bytes(1,'big')
    pad = blocklength - len(byte_file) % blocklength
    return byte_file + pad*pad.to_bytes(1,'big')

# strips padding using pkcs#7
def strip_pad(byte_file):
    pad = byte_file[-1]
    if byte_file[-pad:] != pad*pad.to_bytes(1,'big'):
        raise Exception("Invalid padding")
    return byte_file[:-pad]

def c9():
    bf = b'YELLOW SUBMARINE'
    return pad_file(bf, blocklength=20)

def c10():
    with open('c10.txt', 'r') as f:
        byte_file = b''.join([base64.b64decode(l.strip()) for l in f])
    iv = bytes(16)
    key = b'YELLOW SUBMARINE'
    return cbc.aes_128_cbc_decrypt(iv+byte_file, key)

# returns 16 random bytes
def random_key(length=16):
    return os.urandom(length)

# encrypts a byte file under ecb mode with aes
def ecb_aes_encrypt(pt, key):
    blocksize = 16
    padded_pt = pad_file(pt)
    blocks = [padded_pt[i:i+blocksize] for i in range(0, len(padded_pt), blocksize)]
    return b''.join([aes.encrypt(b, key) for b in blocks])

# decrypts a file encrypted with aes with ecb mode
def ecb_aes_decrypt(ct, key):
    blocksize = 16
    blocks = [ct[i:i+blocksize] for i in range(0,len(padded_pt), blocksize)]
    return strip_pad(b''.join([aes.decrypt(b, key) for b in blocks]))

# encrypts a file randomly with ecb mode or cbc mode
def encryption_oracle(input_bytes):
    pt = bytes(random.randint(5,10)) + input_bytes + bytes(random.randint(5,10))
    print(type(pt))
    if random.randint(1,2) == 1:
        return ("ecb",ecb_aes_encrypt(pt, random_key()))
    else:
        return ("cbc",cbc.aes_128_cbc_encrypt(pt, random_key())[16:])

#takes a byte file and determines if it was encrypted with aes ecb mode
def isECBEncrypted(byte_file):
    if len(byte_file) % 16 != 0:
        return False
    words = [byte_file[i:i+16] for i in range(0,len(byte_file), 16)]
    if len(set(words)) < len(words):
        return True
    return False

def c11():
    pt = bytes(60)
    s, ct = encryption_oracle(pt)
    if (s != 'ecb') != isECBEncrypted(ct):
        print("success!")
    else:
        print("failure")
    
# todo:
# fix cbc part
