# Mersenne Twister PRNG
# For education purposes, should NOT be used for crypto
class Mt19937:
    def __init__(self, seed):
        n = 624
        f = 1812433253
        w = 32
        if seed >> 32 != 0:
            raise Exception("Seed too large")
        
        self.state_array = [0]*n
        self.state_index = 0
        self.state_array[0] = seed
        
        for i in range(1, n):
            seed = (f * (seed ^ (seed >> (w-2)))) % (1 << 32) + i;
            self.state_array[i] = seed
    
    def random_32bits(self):
        w,n,m,r=32, 624, 397, 31
        a = 0x9908b0df
        u,d = 11, 0xffffffff
        s,b = 7, 0x9d2c5680
        t,c = 15, 0xefc60000
        l = 18
        f = 1812433253
        UMASK = (d << r) % (1 << 32)
        LMASK = (d >> (w-r))
        
        k = self.state_index
        
        j = k-(n-1)
        if j < 0:
            j += n

        x = (self.state_array[k] & UMASK) | (self.state_array[j] & LMASK);
        
        xA = x >> 1;
        if x & 0x00000001:
            xA ^= a;
            
        j = k - (n-m);
        if j < 0:
            j += n;

        x = self.state_array[j] ^ xA;
        self.state_array[k] = x;
        k += 1
        
        if k >= n:
            k = 0;
        self.state_index = k
        
        y = x ^ (x >> u);
        y = y ^ (((y << s) % (1<<32)) & b);
        y = y ^ (((y << t) % (1 << 32)) & c);
        z = y ^ (y >> l);

        return z
