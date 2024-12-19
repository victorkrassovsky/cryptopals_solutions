import numpy as np


SBOX_text = """63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84
53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8
51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73
60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79
e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a
70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e
e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df
8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16"""

#initialization of sbox and inverse
SBOX = SBOX_text.split("\n")
SBOX = [x.split(" ") for x in SBOX]
SBOX = [[bytes.fromhex(x) for x in y] for y in SBOX]

SBOX_INVERSE = [None]*256
SBOX_INVERSE = [SBOX_INVERSE[i:i+16] for i in range(0,len(SBOX_INVERSE),16)]

for i in range(16):
    for j in range(16):
        pos = int.from_bytes(SBOX[i][j],'big')
        SBOX_INVERSE[pos//16][pos%16] = (16*i+j).to_bytes(1,'big')
        
#takes a single byte and returns the sbox applied to it
def bytesub_forward_single(b):
    pos = int.from_bytes(b)
    return SBOX[pos//16][pos % 16]

#takes a single byte and returns inverse sbox applied to it
def bytesub_backward_single(s):
    pos = int.from_bytes(s)
    return SBOX_INVERSE[pos//16][pos % 16]

#takes a 4x4 array of ints and applies the sbox operation to it
def bytesub_forward(byte_array):
    for i in range(4):
        for j in range(4):
            byte_array[i][j] = int.from_bytes(bytesub_forward_single(byte_array[i][j].to_bytes(1,'big')),'big')
    return byte_array

#takes a 4x4 array of ints and applies the sbox operation to it
def bytesub_backward(byte_array):
    for i in range(4):
        for j in range(4):
            byte_array[i][j] = int.from_bytes(bytesub_backward_single(byte_array[i][j].to_bytes(1,'big')),'big')
    return byte_array
    
#takes a 4x4 array of ints and performs the shiftrows operation on them
def shiftrows_forward(byte_arr):
    return np.stack([byte_arr[0],np.roll(byte_arr[1],-1),np.roll(byte_arr[2],-2),np.roll(byte_arr[3],-3)]).tolist()

#takes a 4x4 array of ints and performs the reverse shiftrows operation on them
def shiftrows_backward(byte_arr):
    return np.stack([byte_arr[0],np.roll(byte_arr[1],1),np.roll(byte_arr[2],2),np.roll(byte_arr[3],3)]).tolist()


#galois multiplication tables
def gm1(b):
    return b

def gm2(b):
    return ((b << 1) ^ (0x1b & ((b >> 7) * 0xff))) & 0xff

def gm3(b):
    return gm2(b) ^ b

def gm4(b):
    return gm2(gm2(b))

def gm8(b):
    return gm4(gm2(b))

def gm9(b):
    return gm8(b) ^ b

def gm11(b):
    return gm8(b) ^ gm2(b) ^ b

def gm13(b):
    return gm8(b) ^ gm4(b) ^ b

def gm14(b):
    return gm8(b) ^ gm4(b) ^ gm2(b)

#mixes a single column
def mixcolumn_forward_single(c):
    return [(gm2(c[0]) ^ gm3(c[1]) ^ gm1(c[2]) ^ gm1(c[3])),
            (gm1(c[0]) ^ gm2(c[1]) ^ gm3(c[2]) ^ gm1(c[3])),
            (gm1(c[0]) ^ gm1(c[1]) ^ gm2(c[2]) ^ gm3(c[3])),
            (gm3(c[0]) ^ gm1(c[1]) ^ gm1(c[2]) ^ gm2(c[3]))]

#takes a 4x4 array of bytes and performs the mixcolumn operation on them
def mixcolumn_forward(byte_arr):
    byte_arr = np.array(byte_arr)
    c1 = byte_arr[:,0]
    c2 = byte_arr[:,1]
    c3 = byte_arr[:,2]
    c4 = byte_arr[:,3]
    d1 = mixcolumn_forward_single(c1)
    d2 = mixcolumn_forward_single(c2)
    d3 = mixcolumn_forward_single(c3)
    d4 = mixcolumn_forward_single(c4)
    return np.stack([d1,d2,d3,d4], axis=1).tolist()

#inverse mixes a single column 
def mixcolumn_backward_single(d):
    return [(gm14(d[0]) ^ gm11(d[1]) ^ gm13(d[2]) ^ gm9(d[3])),
            (gm9(d[0]) ^ gm14(d[1]) ^ gm11(d[2]) ^ gm13(d[3])),
            (gm13(d[0]) ^ gm9(d[1]) ^ gm14(d[2]) ^ gm11(d[3])),
            (gm11(d[0]) ^ gm13(d[1]) ^ gm9(d[2]) ^ gm14(d[3]))]

#takes a 4x4 array of bytes and performs the inverse mixcolumn operation on them
def mixcolumn_backward(byte_arr):
    byte_arr = np.array(byte_arr)
    d1 = byte_arr[:,0]
    d2 = byte_arr[:,1]
    d3 = byte_arr[:,2]
    d4 = byte_arr[:,3]
    c1 = mixcolumn_backward_single(d1)
    c2 = mixcolumn_backward_single(d2)
    c3 = mixcolumn_backward_single(d3)
    c4 = mixcolumn_backward_single(d4)
    return np.stack([c1,c2,c3,c4],axis=1).tolist()

#rotates a single word for the key-expansion algorithm
def rotword(word):
    a = word[0]
    b = word[1]
    c = word[2]
    d = word[3]
    return b.to_bytes(1,'big')+c.to_bytes(1,'big')+d.to_bytes(1,'big')+a.to_bytes(1,'big')

#applies the sbox to a single word for the key-expansion algorithm
def subword(word):
    return (bytesub_forward_single(word[0].to_bytes(1,'big')) +
            bytesub_forward_single(word[1].to_bytes(1,'big')) +
            bytesub_forward_single(word[2].to_bytes(1,'big')) +
            bytesub_forward_single(word[3].to_bytes(1,'big')))

#applies the rcon transformation to a single word for the key-expansion algorithm
def rcon(word, r):
    round_constants = [None,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
    rc = round_constants[r].to_bytes(4,'little')
    return bytes(a^b for a,b in zip(word,rc))
                 

#takes 16 bytes and expands to 176 bytes, an array of 11 16 byte keys
def key_expansion(K):
    keys = [None]*11
    words = [K[i:i+4] for i in range(0, len(K)-3, 4)]
    keys[0] = words[0]+words[1]+words[2]+words[3]
    for i in range(1,11):
        words[0] = bytes(a^b for a,b in zip(words[0],rcon(subword(rotword(words[3])),i)))
        words[1] = bytes(a^b for a,b in zip(words[0],words[1]))
        words[2] = bytes(a^b for a,b in zip(words[1],words[2]))
        words[3] = bytes(a^b for a,b in zip(words[2],words[3]))
        keys[i] = words[0]+words[1]+words[2]+words[3]
    return keys

#xors two 4x4 arrays of ints
def xor_4x4_arrays(a,b):
    result = [None]*16
    result = [result[i:i+4] for i in range(0,16,4)]
    for i in range(4):
        for j in range(4):
            result[i][j] = a[i][j] ^ b[i][j]
    return result

#16 bytes to 4x4 array of ints
def to_4x4(array):
    array = [x for x in array]
    return np.array([array[i:i+4] for i in range(0,len(array)-3,4)]).T.tolist()

def matrix_to_bytes(mat):
    return b''.join([bytearray(x) for x in np.array(mat).T.tolist()])
    
#takes a 16 byte plaintext and encrypts it with the given 16 byte key using AES
def encrypt(pt, key):
    round_keys = key_expansion(key)
    round_keys = [to_4x4(x) for x in round_keys]
    ct_array = to_4x4(pt)
    ct_array = xor_4x4_arrays(ct_array, round_keys[0])
    for i in range(1,11):
        ct_array = bytesub_forward(ct_array)
        ct_array = shiftrows_forward(ct_array)
        if i != 10:
            ct_array = mixcolumn_forward(ct_array)
        ct_array = xor_4x4_arrays(ct_array,round_keys[i])
    return matrix_to_bytes(ct_array)

#takes a 16 byte ciphertext and decrypts it with the given 16 byte key using AES
def decrypt(ct, key):
    round_keys = key_expansion(key)
    round_keys = [to_4x4(x) for x in round_keys]
    ct_array = to_4x4(ct)
    for i in range(10,0,-1):
        ct_array = xor_4x4_arrays(ct_array,round_keys[i])
        if i != 10:
            ct_array = mixcolumn_backward(ct_array)
        ct_array = shiftrows_backward(ct_array)
        ct_array = bytesub_backward(ct_array)
    ct_array = xor_4x4_arrays(ct_array, round_keys[0])
    return matrix_to_bytes(ct_array)
