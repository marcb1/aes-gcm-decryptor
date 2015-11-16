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

    // read fileName, encrypt it and write result to cipherFile
    int gcmEncryptFile(const std::string& plainFile, const std::string& cipherFile);

    // encrypt plain string and return the encrypted result as a string
    std::string gcmEncryptString(const std::string& plain);

    // read plain String, encrypt it and write result to cipher file
    int gcmEncryptStringtoFile(const std::string& plainString, const std::string& cipherFile);



    // read fileName, decrypt it and write result to decryptedFile
    int gcmDecryptFile(const std::string& decryptedFile, const std::string& cipherFile);

    // read fileName, decrypt it and updated decryptedString
    int gcmDecryptFiletoString(const std::string& fileName, std::string& decryptedString);

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
