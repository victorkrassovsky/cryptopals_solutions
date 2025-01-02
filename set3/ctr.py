import numpy as np
import aes128
import os

#xors two byte blocks of different sizes
def xor_blocks(b1,b2):
    if(len(b1)>len(b2)):
        return bytes(a^b for a,b in zip(b1[:len(b2)],b2))
    else:
        return bytes(a^b for a,b in zip(b1,b2[:len(b1)]))

#converts an array of bytes to a single byte string
def array_to_string(arr):
    return b''.join(arr)

#takes a byte string, 16 byte key and an optional nonce, and encrypts using aes128 ctr mode
#returns a string of bytes corresponding to the cipher text
def ctr_encrypt(pt, key, nonce=os.urandom(8), endian='big'):
    ct_array = None*(len(pt)/8)
    for i in range(0,len(pt_array)):
        counter = i.to_bytes(8,endian)
        block = aes128.encrypt(nonce + counter,key)
        ct_array[i] = xor_blocks(block,pt_array[i])
    return nonce + bytes(8) + array_to_string(ct_array)


#takes a string of bytes returned from encrypt method and returns corresponding plaintext
def ctr_decrypt(ct, key, endian='big'):
    nonce = ct[0:16]
    ct = ct[16:]
    ct_array = [ct[i:i+16] for i in range(0,len(ct), 16)]
    pt_array = [None]*len(ct_array)
    for i in range(0,len(pt_array)):
        counter = (int.from_bytes(nonce[8:16],endian) + i).to_bytes(8,endian)
        block = aes128.encrypt(nonce[0:8]+counter,key);
        pt_array[i] = xor_blocks(block,ct_array[i]);
    return b''.join(pt_array)


