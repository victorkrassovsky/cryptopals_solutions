import base64
import cbc

# pads a byte file to a desired length using pkcs#7 
def pad_file(byte_file, blocklength=16):
    if blocklength > 255:
        raise Exception("Blocklength too large")
    if len(byte_file) % blocklength == 0:
        return byte_file + blocklength*blocklength.to_bytes(1,'big')
    pad = blocklength - len(byte_file) % blocklength
    return byte_file + pad*pad.to_bytes(1,'big')

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

