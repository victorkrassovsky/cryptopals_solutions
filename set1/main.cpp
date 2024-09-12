#include <iostream>
#include <assert.h>
#include "c1/c1.h"
#include "c2/c2.h"

int main(){
  std::cout << "Tests: \n";
  std::cout << xor_hex_strings("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965");
}
