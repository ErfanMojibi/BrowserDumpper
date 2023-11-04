#pragma once


unsigned char* base64_decode(const char* data, SIZE_T input_length, SIZE_T* output_length);
char* base64_encode(const unsigned char* data, SIZE_T input_length, SIZE_T* output_length);
void build_decoding_table();
void base64_cleanup();