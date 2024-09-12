#include <iostream>
#include "../c1/c1.h"
#include "c2.h"

char hex_char_lookup(int a){
  if (0 <= a && a <= 9){
    return '0' + a;
  }
  return 'a' + a - 10;
}

char* bytes_to_hex(byte_array b){
  char* str = (char*) malloc(sizeof(char)*b.size*2 + 1);
  str[b.size*2] = '\0';
  for (int i = 0; i < b.size*2; i += 2){
    str[i] = hex_char_lookup(b.bytes[i/2]/16);
    str[i+1] = hex_char_lookup(b.bytes[i/2]%16);
  }
  return str;
}


char* xor_hex_strings(char* h1, char* h2){
  byte_array b1 = hex_to_bytes(h1);
  byte_array b2 = hex_to_bytes(h2);
  byte_array out = {(int*) malloc(sizeof(int)*b1.size), b1.size};
  for (int i = 0; i < out.size; i++){
    out.bytes[i] = b1.bytes[i] ^ b2.bytes[i];
  }
  free(b1.bytes);
  free(b2.bytes);
  char* st = bytes_to_hex(out);
  free(out.bytes);
  
  return st;
}



