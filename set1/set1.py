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

letterFrequency = {'E' : 12.0,
'T' : 9.10,
'A' : 8.12,
'O' : 7.68,
'I' : 7.31,
'N' : 6.95,
'S' : 6.28,
'R' : 6.02,
'H' : 5.92,
'D' : 4.32,
'L' : 3.98,
'U' : 2.88,
'C' : 2.71,
'M' : 2.61,
'F' : 2.30,
'Y' : 2.11,
'W' : 2.09,
'G' : 2.03,
'P' : 1.82,
'B' : 1.49,
'V' : 1.11,
'K' : 0.69,
'X' : 0.17,
'Q' : 0.11,
'J' : 0.10,
'Z' : 0.07 }

def score(s):
    total = 0
    for c in s:
        if(c in letterFrequency.keys()):
            total += letterFrequency[c]
        else:
            total -= 2
    return total

def single_byte_xor(hex_string):
    b = bytes.fromhex(hex_string)
    best_score = 0;
    best_i = 0;
    for i in range(256):
        decrypted_bytes = b''.join([(i^x).to_bytes(1,'big') for x in b])
        if (all([(x > 31 and x < 127) for x in decrypted_bytes])
            and best_score < score(decrypted_bytes.decode('utf-8'))):
            best_score = score(decrypted_bytes.decode('utf-8'))
            best_i = i
    return (best_i, b''.join([(best_i^x).to_bytes(1,'big') for x in b]).decode('utf-8'))
            
#c4
