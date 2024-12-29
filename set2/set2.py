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
    if type(byte_file) != bytes:
        raise Exception("Not bytes")
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
def ecb_aes_decrypt(ct, key, padded=True):
    blocksize = 16
    blocks = [ct[i:i+blocksize] for i in range(0,len(ct), blocksize)]
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


# has a secret key and an target string to be recovered
# key was randomly generated
# returns ecb(pt + target, key)
def c12oracle(pt):
    if type(pt) != bytes:
        raise Exception("Not bytes")
    key = b'\x0e7\xb1\xba\xdf\xcb\x1a\x0cR\xb2/\xee\xaf0\x9c\x86'
    target = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    return ecb_aes_encrypt(pt + target, key)

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
    # recover each byte one at a time
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
def parse_query(s):
    s_split = s.split('&')
    pairs = [pair.split("=") for pair in s_split]
    return dict(pairs)

# converts a dict to a query parameter of a url
def to_query(d):
    return ''.join([k + "=" + v + "&" for k,v in d.items()])[:-1]

# makes a query string out of an email
def profile_for(email):
    email = email.replace('&', '')
    email = email.replace('=', '')
    email_text = re.search(".+@.+\.com", email).string
    return {"email":email_text, "uid" : "10", "role":"user"}

# encrypts user profile in query form under a secret key
# accepts a normal string
def encrypt_user_profile(p):
    key = b'{\x90\xe6~,\x19\xd3bO\x95\x9d(\xb4\xf8\xf1\x11'
    return ecb_aes_encrypt(bytes(p,'utf-8'), key)

# decrypts user profile under a secret key
# accepts a bytes strig
def decrypt_user_profile(ct):
    key = b'{\x90\xe6~,\x19\xd3bO\x95\x9d(\xb4\xf8\xf1\x11'
    return parse_query(str(ecb_aes_decrypt(ct, key), 'utf-8'))

# this is the byte file the attacker has access to
def makeProfile(email):
    return encrypt_user_profile(to_query(profile_for(email)))

# procudes a valid admin profile
def c13():
    e1 = "1234@5678.com"
    e2 = 'A'*10 + "admin" + '\x0b'*11 + '@holyhell.com'
    result = makeProfile(e1)[:-16] + makeProfile(e2)[16:32]
    return decrypt_user_profile(result)

# accepts a byte file and encrypts under ecb mode with some appendages
# returns ecb(set-random-prefix || input || target, set-random-key)
def c14oracle(byte_file):
    key = b'\x8c\xfc\x00<M\xff7\x88\x91\xe2\x0b\xf6\xcf\x08?w'
    prefix = b'.\x1f\x88Y\xbf\xea\xf2\x33\x45\xb4'
    # same as in c12
    target = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    return ecb_aes_encrypt(prefix+byte_file+target, key)

# finds the target hidden in the oracle
def c14():
    # determine blocklength
    least_length = len(c14oracle(b''))
    for i in range(1, 32):
        cur_length = len(c14oracle(bytes(i)))
        if cur_length > least_length:
            blocklength = cur_length - least_length
            pad = i
            total_length = least_length - i
            break
        
    # confirm that ecb is used
    padded_ct = c14oracle(bytes(blocklength*3))
    if not isECBEncrypted(padded_ct):
        raise Exception("Not ecb encrypted")
    if len(padded_ct) % blocklength != 0:
        raise Exception("ciphertext has wrong size")
    
    # find number of bytes in target/prefix
    padded_ct_blocks = [padded_ct[i:i+blocklength] for i in range(0,len(padded_ct), 16)]
    for i,x in enumerate(padded_ct_blocks[:-1]):
        if x == padded_ct_blocks[i+1]:
            zeros_ct = x

    for prefix_pad in range(0,blocklength):
        temp_ct = c14oracle(bytes(prefix_pad + blocklength))
        if zeros_ct in temp_ct:
            prefix_offset = temp_ct.find(zeros_ct)
            break
    target_pad = pad - prefix_pad
    prefix_length = prefix_offset - prefix_pad
    target_length = total_length - prefix_length
    
    # recover each byte one at a time
    # WILL TAKE A LONG TIME
    result = bytearray(target_length + blocklength - 1)
    for i in range(target_length):
        indent = (blocklength-1-i) % blocklength
        slide = prefix_offset + (i//blocklength)*blocklength
        target_ct = c14oracle(bytes(prefix_pad + indent))[slide:slide+blocklength]
        print(i)
        for j in range(0,255):
            candidate_byte = j.to_bytes(1,'big')
            candidate_pt = bytes(prefix_pad) + bytes(result[i:i+blocklength-1]) + candidate_byte
            candidate_ct = c14oracle(candidate_pt)[prefix_offset:prefix_offset+blocklength]
            if candidate_ct == target_ct:
                result[i+blocklength-1] = j
                print(j.to_bytes(1,'big'))
                break
            
    return result[blocklength-1:]

# tests the strip_pad function I wrote earlier
def c15():
    try:
        assert(strip_pad(b'asdf' + (12).to_bytes(1,'big')*12) == b'asdf')
        print("test 1 succeeded")
    except AssertionError:
        print("test 1 failed")
    try:
        assert(strip_pad(b'a'*16 + b'\x10'*16) == b'a'*16)
        print("test 2 succeeded")
    except AssertionError:
        print("test 2 failed")
    try:
        assert(strip_pad(b'asdf' + bytes(11) + (12).to_bytes(1,'big')) == b'asdf')
    except Exception:
        print("test 3 succeeded")
    else:
        print("test 3 failed")

# produces a user data string
# takes bytes, removes metacharacters, prepends and appends some stuff
# then encrypts using cbc
def process_input(byte_file):
    key = b'.\xbf\xfd\x0b\x18\x08o8z6\xbb\xad\x1d\xed\xd2\xb6'
    pt = byte_file.replace(b';',b'').replace(b'=',b'')
    prepend = b'comment1=cooking%20MCs;userdata='
    append = b';comment2=%20like%20a%20pound%20of%20bacon'
    complete_pt = prepend + pt + append
    ct = cbc.aes_128_cbc_encrypt(complete_pt, key)
    return ct

# determines if user is admin
# decrypts bytes and returns whether it contains a string
def has_admin(byte_file):
    key = b'.\xbf\xfd\x0b\x18\x08o8z6\xbb\xad\x1d\xed\xd2\xb6'
    pt = cbc.aes_128_cbc_decrypt(byte_file, key)
    if b';admin=true;' in pt:
        return True
    else:
        return False

# produces a valid admin user
def c16():
    # since length of prepend is a multiple of the blocklength, we can simply ignore it
    ct = process_input(bytes(16))
    key = b'.\xbf\xfd\x0b\x18\x08o8z6\xbb\xad\x1d\xed\xd2\xb6'
    # TODO:
    # Fix issue where zeroes are disappearing for some reason
    return cbc.aes_128_cbc_decrypt(ct, key)
