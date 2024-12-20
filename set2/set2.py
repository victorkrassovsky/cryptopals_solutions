import base64
import aes128 as aes
import cbc
import os
import random
import re

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
    pt = (b'A')*60
    s, ct = encryption_oracle(pt)
    if (s != 'ecb') != isECBEncrypted(ct):
        print(s)
        print("success!")
    else:
        print(s)
        print(ct)


# has a secret key and an unknown string to be recovered
# key was randomly generated
# returns ecb(pt + unknown_str, key)
def c12oracle(pt):
    if type(pt) != bytes:
        raise Exception("Not bytes")
    key = b'\x0e7\xb1\xba\xdf\xcb\x1a\x0cR\xb2/\xee\xaf0\x9c\x86'
    unknown_str = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    return ecb_aes_encrypt(pt + unknown_str, key)

def c12():
    # recover the blocklength:
    s1 = len(c12oracle(bytes(1)))
    s2 = len(c12oracle(bytes(2)))
    for i in range(3,255):
        if s1 < s2:
            j=i-1
            break
        s1 = s2
        s2 = len(c12oracle(bytes(i)))
    blocklength = s2 - s1
    length = s1 - j
    # confirm that it is using ecb mode
    if not isECBEncrypted(c12oracle(bytes(blocklength*3))):
        raise Exception("not ecb encrypted")
    # recover each byte at a time
    # WILL TAKE A LONG TIME
    result = bytearray(length + blocklength - 1)
    for i in range(0,length):
        indent = (blocklength-1-i) % blocklength
        slide = (i//blocklength)*blocklength
        target = c12oracle(bytes(indent))[slide : slide + blocklength]
        for j in range(0,255):
            if target == c12oracle(bytes(result[i:i+blocklength-1]) + j.to_bytes(1,'big'))[:blocklength]:
                result[i+blocklength-1] = j
                break
    return result[blocklength-1:]

# parses the query parameter of a url and makes it a dict
def parseURL(s):
    return dict(re.findall("(\w+)=(\w+)", s))

# converts a dict to a query parameter of a url
def toURL(d):
    return ''.join([k + "=" + v + "&" for k,v in d.items()])[:-1]

# makes a query string out of an email
def profile_for(email):
    email = email.replace('&', '')
    email = email.replace('=', '')
    email_text = re.search("\w+@\w+.com", email).string
    return {"email":email_text, "role":"user"}

# encrypts user profile in query form under a secret key
def encrypt_user_profile(pt):
    key = b'{\x90\xe6~,\x19\xd3bO\x95\x9d(\xb4\xf8\xf1\x11'
    return ecb_aes_encrypt(pt, key)

# decrypts user profile under a secret key
def decrypt_user_profile(ct):
    key = b'{\x90\xe6~,\x19\xd3bO\x95\x9d(\xb4\xf8\xf1\x11'
    ecb_aes_encrypt(ct, key)
    
