import base64
import aes128 as aes

#c1
# converts a hex string to a base 64 string in big endian
def hex_to_64 (h):
    b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890+/"
    hex_table = "0123456789abcdef"
    h = "0"*(len(h)%3) + h
    if h[0:2] == '0x':
        h = h[2:]
    result = ""
    for x in [h[i:i+3] for i in range(0, len(h), 3)]:
        print(x)
        int_value = hex_table.find(x[0])*256 + hex_table.find(x[1])*16 + hex_table.find(x[2])
        result = result + b64[(int_value//64)%64] + b64[int_value % 64]
    return result

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

# takes two equal length hex strings and returns their xor
def hex_xor(h1, h2):
    hex_table = "0123456789abcdef"
    if(h1[0:2] == '0x'):
        h1 = h1[0:2]
    if(h2[0:2] == '0x'):
        h2 = h1[0:2]
    result = ""
    for (c1,c2) in zip(h1, h2):
        result += hex_table[hex_table.find(c1)^hex_table.find(c2)]
    return result

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

#c3

# xors two words of any length, return has length of the shorter word
def xor_bytes(b1, b2):
    if(len(b1) < len(b2)):
        return b''.join([(i^j).to_bytes(1,'big') for i,j in zip(b1, b2[:len(b1)])])
    else:
        return b''.join([(i^j).to_bytes(1, 'big') for i,j in zip(b1[:len(b2)], b2)])

# xors an entire word by a single byte
def xor_single_byte(single, b):
    return xor_bytes(single*len(b), b)

# accepts a byte string that has been xored against a single byte, returns score and the original string
def solve_single_byte_xor(b):
    best_score = 0
    best_i = 0
    for i in range(256):
        curr_string = xor_single_byte(i.to_bytes(), b)
        if not all([x <= 127 for x in curr_string]):
            continue
        curr_score = score(curr_string.decode('utf-8'))
        if(best_score < curr_score):
            best_score, best_i = curr_score, i
    return (best_score, xor_single_byte(best_i.to_bytes(), b), best_i.to_bytes())

def c3():
    hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    b = bytes.fromhex(hex_string)
    return solve_single_byte_xor(b)

#c4

def c4(file_name):
    lines = []
    with open(file_name, 'r') as f:
        lines = [l.strip() for l in f]
    (best_score,best_line) = (-1, b'')
    i = 0
    for line in lines:
        curr_score,curr_line,_ = solve_single_byte_xor(line)
        if(curr_score > best_score):
            best_score = curr_score
            best_line = curr_line
    return (best_score,best_line)

#c5
# encrypts a byte string by xoring it with a multi-byte key
def repeating_key_xor(key, byte_string):
    return b''.join([(byte_string[i] ^ key[i%len(key)]).to_bytes(1, 'big')  for i in range(len(byte_string))])

def c5():
    pt = b'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'
    ct = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    output = repeating_key_xor(b'ICE', pt).hex()
    return ct == output


#c6
# computes the hamming distance between words
def hamming_distance(b1, b2):
    xored = xor_bytes(b1,b2)
    return sum([bin(x).count('1') for x in xored])

# accepts a file of bytes encrypted using repeating_key_xor and recovers the key used to encrypt
def solve_repeating_key_xor(byte_file):
    key_sizes = []
    for candidate in range(2, 40):
        dist = hamming_distance(byte_file[:candidate], byte_file[candidate:2*candidate])/candidate
        key_sizes.append((candidate, dist))
    key_sizes.sort(reverse=True, key=lambda a : a[1])
    results = []
    for (key_size,_) in key_sizes:
        blocks = [byte_file[i:i+key_size] for i in range(0, len(byte_file), key_size)][:-1]
        blocks_transposed = [[blocks[i][j] for i in range(len(blocks))] for j in range(len(blocks[0]))]
        result = b''
        total_score = 0
        for b in blocks_transposed:
            score,pt_block, key = solve_single_byte_xor(b''.join([x.to_bytes(1, 'big') for x in b]))
            total_score += score
            result += key
        results.append((result, total_score))
    results.sort(reverse=True, key=lambda a: a[1])
    return results[0]
    
def c6():
    with open("c6_text.txt", 'r') as f:
        byte_file = b''.join([base64.b64decode(l.strip()) for l in f])
    key,_ = solve_repeating_key_xor(byte_file)
    
    return repeating_key_xor(key, byte_file), key

#c7
def c7():
    with open("c7_text.txt", 'r') as f:
        byte_file = b''.join([base64.b64decode(l.strip()) for l in f]);
    result = b''
    key = b'YELLOW SUBMARINE'
    for word in [byte_file[i:i+16] for i in range(0, len(byte_file), 16)]:
        result += aes.decrypt(word, key)
    return c7

#takes a byte file and determines if it was encrypted with aes ecb mode
def isAESEncrypted(byte_file):
    if len(byte_file) % 16 != 0:
        return False
    words = [byte_file[i:i+16] for i in range(0,len(byte_file), 16)]
    if len(set(words)) < len(words):
        return True
    return False
    
def c8():
    with open('c8.txt', 'r') as f:
        byte_file = [bytes.fromhex(l.strip()) for l in f]
    for (i,bf) in zip(range(len(byte_file)),byte_file):
        if isAESEncrypted(bf):
            return bf, i
        
