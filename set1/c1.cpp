#include <iostream>
#include <string.h>

char* hex_to_64(char* hex_string){
    return NULL;
}

int hex_lookup(char p){
    if('0' <= p && p <= '9'){
        return (int)(p-'0');
    }
    if('a'<= p && p <= 'f'){
        return (int)(p-'a'+10);
    }
    return NULL;
}

int* hex_to_bytes(char* hex_string){
    int *byte_arr = (int*)malloc(sizeof(int) * (strlen(hex_string)/2));
    for (int i = 0; i < strlen(hex_string); i += 2) {
        byte_arr[i/2] = hex_lookup(hex_string[i])*16 + hex_lookup(hex_string[i+1]); 
    }
    return byte_arr;
}

char* bytes_to_64(int* byte_array){
    return NULL;
}



int main(int args[]){
    char* hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    int* p = hex_to_bytes(hex);
    for (int i = 0; i < 5; i++){
        std::cout << p[i] << "\n";
    }
    

    
}