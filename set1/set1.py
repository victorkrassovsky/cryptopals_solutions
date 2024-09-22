import base64

#c1

def hex_to_b64 (hex_string):
    b = bytes.fromhex(hex_string);
    return base64.b64encode(b)

#c2

#both h1 and h2 must be the same length
def xor_hex_strings(h1, h2):
    b1 = bytes.fromhex(h1)
    b2 = bytes.fromhex(h2)
    b = b''.join([(x ^ y).to_bytes(1,'big') for x,y in zip(b1,b2)])
    return b.hex()

#c3

def single_byte_xor(hex_string):
    b = bytes.fromhex(hex_string)
    for i in range(256):
        decrypted_bytes = b''.join([(i^x).to_bytes(1,'big') for x in b])
        if(all([(x > 32 and x < 127) for x in decrypted_bytes])):
           return (i, decrypted_bytes.decode('utf-8'))
    return (-1, 'RIP')
        
#c4
