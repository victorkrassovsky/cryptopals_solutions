import numpy as np
import aes128
import os

# xors two byte blocks of different sizes
def xor_blocks(b1,b2):
    if(len(b1)>len(b2)):
        return bytes(a^b for a,b in zip(b1[:len(b2)],b2))
    else:
        return bytes(a^b for a,b in zip(b1,b2[:len(b1)]))

# converts an array of bytes to a single byte string
def array_to_string(arr):
    return b''.join(arr)

# yields a generator which gives padding blocks for ctr mode
# nonce required
def get_stream(key, byte_count, nonce, endian='big'):
    for i in range(byte_count):
        counter = nonce + i.to_bytes(8,endian)
        yield aes128.encrypt(counter, key)
    
# takes a byte string, 16 byte key and an optional nonce, and encrypts using aes128 ctr mode
# returns a string of bytes corresponding to the cipher text
def ctr_encrypt(pt, key, nonce=os.urandom(8), endian='big'):
    if len(nonce) != 8:
        raise Exception("Nonce has incorrect length")
    pt_array = [pt[i:i+16] for i in range(0, len(pt), 16)]
    pad_array = [pad for pad in get_stream(key, len(pt_array), nonce, endian=endian)]
    ct_array = [xor_blocks(pt_block, pad_block) for pt_block, pad_block in zip(pt_array, pad_array)]  
    return nonce + bytes(8) + array_to_string(ct_array)


# takes a string of bytes returned from encrypt method and returns corresponding plaintext
def ctr_decrypt(ct, key, endian='big'):
    if len(ct) < 16:
        raise Exception("Ciphertext too short")
    nonce = ct[0:8]
    ct = ct[16:]
    return ctr_encrypt(ct, key, nonce=nonce, endian=endian)[16:]

