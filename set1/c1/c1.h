#include <iostream>

struct byte_array{
  int* bytes;
  int size;
};

byte_array hex_to_bytes(char*);

char* bytes_to_64(byte_array);

char* hex_to_64(char*);
