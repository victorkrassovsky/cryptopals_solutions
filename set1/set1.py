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

letterFrequency = {'e' : 12.0,
't' : 9.10,
'a' : 8.12,
'o' : 7.68,
'i' : 7.31,
'n' : 6.95,
's' : 6.28,
'r' : 6.02,
'h' : 5.92,
'd' : 4.32,
'l' : 3.98,
'u' : 2.88,
'c' : 2.71,
'm' : 2.61,
'f' : 2.30,
'y' : 2.11,
'w' : 2.09,
'g' : 2.03,
'p' : 1.82,
'b' : 1.49,
'v' : 1.11,
'k' : 0.69,
'x' : 0.17,
'q' : 0.11,
'j' : 0.10,
'z' : 0.07 }

common_digraphs = "th er on an re he in ed nd ha at en es of or nt ea ti to it st io le is ou ar as de rt ve"
common_digraphs = common_digraphs.split(' ')

def score(s):
    total = 0
    for c in s:
        if(c in letterFrequency.keys()):
            total += letterFrequency[c]
    for i in range(0,len(s)-2):
        if s[i:i+2] in common_digraphs:
            total += 10
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
    return (best_i, b''.join([(best_i^x).to_bytes(1,'big') for x in b]))
            
#c4
