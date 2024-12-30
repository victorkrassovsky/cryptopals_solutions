import numpy as np
import aes128
import os

# xors two byte strings of possibly different lengths
def xor_strings(a,b):
    if type(a) != type(b) or type(a) != bytes:
        raise Exception("Not bytes")
    if len(a) < len(b):
        return b''.join([(x^y).to_bytes(1,'big') for x,y in zip(a, b[:len(a)])])
    else:
        return b''.join([(x^y).to_bytes(1,'big') for x,y in zip(a[:len(b)], b)])
    
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
    if type(byte_file) != bytes:
        raise Exception("Not bytes")
    pad = byte_file[-1]
    if byte_file[-pad:] != pad*pad.to_bytes(1,'big'):
        raise Exception("Invalid padding")
    return byte_file[:-pad]

#takes a string of bytes, a 16 byte key and an optional iv and applies the cbc mode aes cipher to it
def cbc_encrypt(pt, key, iv=os.urandom(16)):
    pt = pad_file(iv + pt)
    pt_array = [pt[i:i+16] for i in range(0,len(pt),16)]
    ct_array = [None]*len(pt_array)
    ct_array[0] = pt_array[0]
    for i in range(1, len(pt_array)):
        ct_array[i] = aes128.encrypt(xor_strings(ct_array[i-1],pt_array[i]),key)
    return b''.join(ct_array)

#takes a string of bytes returned from the encrypt function and returns the corresponding plaintext as a string of bytes
def cbc_decrypt(ciphertext, key):
    ct_array = [ciphertext[i:i+16] for i in range(0,len(ciphertext),16)]
    pt_array = [None]*(len(ct_array)-1)
    for i in range(0, len(pt_array)):
        pt_array[i] = bytes(a^b for a,b in zip(aes128.decrypt(ct_array[i+1],key), ct_array[i]))
    pt = b''.join([bytearray(x) for x in np.array(pt_array).T.tolist()])
    pt = strip_pad(pt)
    return pt
    
