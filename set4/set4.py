import aes128 as aes
import os
import ctr
import base64 as b64

# def edit(ct, ):
#     key = b"\xe2f\x96\x97'\xcd\x7f\x12\xec\xbc\xce\x00\xba0\xea\x9f"

# # breaks ctr mode with access to the edit function
# def c25():
#     key = b"\xe2f\x96\x97'\xcd\x7f\x12\xec\xbc\xce\x00\xba0\xea\x9f"
#     nonce = os.urandom(8)
#     with open('c25.txt', 'r') as f:
#         lines = b''.join([b64.b64decode(l.strip()) for l in f])
#         byte_file = ctr.ctr_encrypt(lines, key, nonce=nonce)

# produces a user data string
# takes bytes, removes metacharacters, prepends and appends some stuff
# then encrypts using cbc
def process_input(byte_file):
    key = b'.\xbf\xfd\x0b\x18\x08o8z6\xbb\xad\x1d\xed\xd2\xb6'
    pt = byte_file.replace(b';',b'').replace(b'=',b'')
    prepend = b'comment1=cooking%20MCs;userdata='
    append = b';comment2=%20like%20a%20pound%20of%20bacon'
    complete_pt = prepend + pt + append
    ct = ctr.ctr_encrypt(complete_pt, key)
    return ct

# determines if user is admin
# decrypts bytes and returns whether it contains a string
def has_admin(byte_file):
    key = b'.\xbf\xfd\x0b\x18\x08o8z6\xbb\xad\x1d\xed\xd2\xb6'
    pt = ctr.ctr_decrypt(byte_file, key)
    if b';admin=true;' in pt:
        return True, pt
    else:
        return False,pt

# xors two byte strings of possibly different lengths
def xor_strings(a,b):
    if len(a) < len(b):
        return b''.join([(x^y).to_bytes(1,'big') for x,y in zip(a, b[:len(a)])])
    else:
        return b''.join([(x^y).to_bytes(1,'big') for x,y in zip(a[:len(b)], b)])

# produces a valid admin user
# NOTE: could be cleaner since there are out of place metacharacters in the final plaintext,
# and incorrectly formatted query parameters, but these can be fixed with some work
def c26():
    # since length of prepend is a multiple of the blocklength, we can simply ignore it
    ct = process_input(b'\x00' * 16)
    key = b'.\xbf\xfd\x0b\x18\x08o8z6\xbb\xad\x1d\xed\xd2\xb6'
    ct_blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    index = 4 # index of the 0s block
    transform = xor_strings(b';comment2=%20lik', b';admin=true;' + bytes(4))
    ct_blocks[index] = xor_strings(transform, ct_blocks[index])
    out = b''.join(ct_blocks)
    return has_admin(out)
