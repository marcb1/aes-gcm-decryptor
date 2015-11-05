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

    int gcmEncryptFile(IStream* cipherStream, IStream* plainStream);

    int gcmEncryptFile(const char* plainFile, const char* cipherFile);

    int gcmDecryptFile(const char* decryptedFile, const char* cipherFile);

    int gcmDecryptFile(const char* cipherFile, IStream* stream);

    int gcmDecryptFile(IStream* cipherStream, IStream* plainStream);


    int gcmEncryptString(std::string plain, const char* cipherFile);

  private:
    int gcmEncrypt(IStream* plainStream, unsigned char *key_buf, IStream* cipherStream);

    int gcmDecrypt(int fd, size_t file_len, unsigned char *key_buf, IStream* outStream);

    unsigned char*        _key;
    const EVP_CIPHER*     _cipher;
};
