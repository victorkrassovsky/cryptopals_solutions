#include <iostream>
#include <string.h>


// everything is REALLY unsafe

struct byte_array{
    int* bytes;
    size_t size;
};

int hex_lookup(char p){
    if('0' <= p && p <= '9'){
        return (int)(p-'0');
    }
    if('a'<= p && p <= 'f'){
        return (int)(p-'a'+10);
    }
    return NULL;
}

byte_array hex_to_bytes(char* hex_string){
    byte_array byte_arr = {(int*)malloc(sizeof(int) * (strlen(hex_string)/2)), strlen(hex_string)/2} ;
    for (int i = 0; i < strlen(hex_string); i += 2) {
        byte_arr.bytes[i/2] = hex_lookup(hex_string[i])*16 + hex_lookup(hex_string[i+1]); 
    }
    return byte_arr;
}

char b64_lookup(int k){
    if(0 <= k && k <= 25){
        return 'A' + k;
    }
    else if(26 <= k && k <= 51){
        return 'a' + k - 26;
    }
    else if(52 <= k && k <= 61){
        return '0' + k - 52;
    }
    else if(k == 62){
        return '+';
    }
    else if(k == 63){
        return '/';
    }
    return '=';
}

char* bytes_to_64(byte_array arr){
    char* b64 = (char*) malloc(sizeof(char)*((arr.size*4)/3 + 1));
    b64[arr.size*4/3] = '\0';
    for (int i = 0, j = 0; i < arr.size-2; i += 3){
        int a = arr.bytes[i];
        int b = arr.bytes[i+1];
        int c = arr.bytes[i+2];
        b64[j++] = b64_lookup(a/4);
        b64[j++] = b64_lookup((a % 4) * 16 + b/16);
        b64[j++] = b64_lookup((b % 16) * 4 + c/64);
        b64[j++] = b64_lookup(c % 64);
    }
    return b64;
}

char* hex_to_64(char* hex_string){
    return bytes_to_64(hex_to_bytes(hex_string));
}


