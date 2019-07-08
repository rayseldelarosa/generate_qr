/*
Author: Raysel
Tested with OpenSSL 1.1.1 and C++11
To execute the code, run command:
    "g++ ./main.cpp -o ./main.o -g -lcrypto -Wall -std=c++11 && ./main.o"
*/
#include "library.h"

#include <iostream>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

using namespace std;

#define KEY_LEN      32
#define ITERATION     1

unsigned char *iv_out, *ciphertext_out;
int iv_out_len = 0, ciphertext_out_len = 0;

// Same functionality that binascii.hexlify
char *binascii_hexlify(unsigned char *data, int data_len)
{
    char buffer [10];
    char *result = (char *)malloc(2 * data_len);
    strcpy(result, "");

    int indx = 0;
    for(int i = 0; i < data_len; i++)
    {
        sprintf(buffer, "%02x", data[i]);

        for(int j = 0; j < (int)strlen(buffer); j++)
        {
            result[indx] = buffer[j];
            indx++;
        }
    }

    return result;
}

// returns the length of ciphertext and puts in ciphertext_out the text encrypted
int encrypt(unsigned char* key, unsigned char* plaintext, int plaintext_len)
{
    ciphertext_out = (unsigned char *)malloc(sizeof(unsigned char) * plaintext_len);
    ciphertext_out_len = plaintext_len;

    iv_out = (unsigned char *) malloc(sizeof(unsigned char) * AES_BLOCK_SIZE);
    iv_out_len = AES_BLOCK_SIZE;

    // iv = Random.new().read(AES.block_size)
    // it is not necessary to do "iv_int = int(binascii.hexlify(iv), 16)"
    // because "EVP_aes_128_ctr" recive an "unsigned char *" as an iv
    RAND_bytes(iv_out, AES_BLOCK_SIZE);

    // creating an AES type encryption in CTR mode
    EVP_CIPHER_CTX* cipher = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(cipher, EVP_aes_128_ctr(), NULL, key, iv_out, 1);

    int out_len = ciphertext_out_len;
    // encrypting the text
    EVP_CipherUpdate(cipher, ciphertext_out, &out_len, plaintext, plaintext_len);
    EVP_CipherFinal_ex(cipher, ciphertext_out + out_len, &out_len);

    // deallocate space from cipher
    EVP_CIPHER_CTX_set_padding(cipher, 0);
    EVP_CIPHER_CTX_free(cipher);

    return ciphertext_out_len;
}

unsigned char* generate_key(const char* passValue)
{
    unsigned char *out;
    out = (unsigned char *) malloc(sizeof(unsigned char) * KEY_LEN);

    const char* pass = passValue;

    // same salt "\xeb|\x00\xaf'\x81\xeb\xb4J\x03de\x0eV[/\x02-\xbf\xdd\x82\xf2I\xa5\xdd\x0fQ\xedkk_\x0b"
    unsigned char salt[]= { 0xeb, 0x7c, 0x0, 0xaf, 0x27, 0x81, 0xeb, 0xb4, 0x4a, 0x3, 0x64, 0x65, 0xe, 0x56, 0x5b, 0x2f, 0x2, 0x2d, 0xbf, 0xdd, 0x82, 0xf2, 0x49, 0xa5, 0xdd, 0xf, 0x51, 0xed, 0x6b, 0x6b, 0x5f, 0xb };

    // creating the key for both en and de - crypting
    // key = PBKDF2(password, salt, key_bytes)
    PKCS5_PBKDF2_HMAC_SHA1(pass, strlen(pass), salt, sizeof(salt), ITERATION, KEY_LEN, out);

    return out;
}

char *generate_qr(const char *UID, const char *timestr)
{
    unsigned char *key = generate_key(UID);

    // build a string with JSON format
    const char *text1 = R"({"businessId": ")";
    const char *text2 = R"(", "timestamp": ")";
    const char *text3 = "\"}";

    char *plaintext = (char *)malloc(strlen(text1) + strlen(UID) + strlen(text2) + strlen(timestr) + strlen(text3) + 1);

    strcpy(plaintext, text1);
    strcat(plaintext, UID);
    strcat(plaintext, text2);
    strcat(plaintext, timestr);
    strcat(plaintext, text3);

    // converting (char *) to (unsigned char *) to be able
    // to call encrypt method
    unsigned char uc_plaintext[strlen(plaintext)];

    for(int i = 0; i < (int)strlen(plaintext); i++)
    {
        uc_plaintext[i] = (unsigned char)plaintext[i];
    }

    encrypt(key, uc_plaintext, (int)sizeof(uc_plaintext));

    char *iv_value = binascii_hexlify(iv_out, iv_out_len);
    char *cipher_value = binascii_hexlify(ciphertext_out, ciphertext_out_len);

    // creating a result
    char *data = (char *)malloc((int)strlen(iv_value) + (int)strlen(cipher_value) + 1);
    strcpy(data, iv_value);
    strcat(data, ",");
    strcat(data, cipher_value);

    return data;
}

//int main()
//{
//    char *result = generate_qr("e63cf383e35e40f69cc0238df5269e7c", "2019-07-07 16:57:50.034696");
//    printf("final result - %s\n", result);
//    printf("bytes: %d\n", (int)strlen(result)/2);
//    return 0;
//}
