#pragma once

#include "helpers.h"
#include "IStream.h"


//IV needs to be unique  for each new message but not random
//http://crypto.stackexchange.com/questions/5807/aes-gcm-and-its-iv-nonce-value
#define IV_LEN      16
#define BUF_SIZE    65535

class aesEncryptor
{
  public:
    aesEncryptor(const std::string& key);

    ~aesEncryptor();


    int gcmEncryptFile(const char* plainFile, const char* cipherFile);

    int gcmEncryptString(const std::string& plain, const char* cipherFile);

    // encrypt plain string and return the encrypted result
    std::string gcmEncryptString(const std::string& plain);


    int gcmDecryptFile(const char* decryptedFile, const char* cipherFile);

    // decrypt cipherString and place result into plainString
    std::string gcmDecryptString(const std::string& cipherString);


  private:
    // reads from plainStream and writes encrypted result into cipherStream
    int gcmEncrypt(IStream* plainStream, unsigned char *key_buf, IStream* cipherStream);

    // reads from cipherStream and writes decrypted result into plainStream
    int gcmDecrypt(IStream* cipherStream, unsigned char *key_buf, IStream* plainStream);

    unsigned char*        _key;
    const EVP_CIPHER*     _cipher;
};
