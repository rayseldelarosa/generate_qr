#ifndef UNTITLED_LIBRARY_H
#define UNTITLED_LIBRARY_H

char *binascii_hexlify(unsigned char *data, int data_len);
int encrypt(unsigned char* key, unsigned char* plaintext, int plaintext_len);
unsigned char* generate_key(const char* passValue);
char *generate_qr(const char *UID, const char *timestr);


#endif //UNTITLED_LIBRARY_H