#include "aesEncryptor.h"
#include "FileStream.h"
#include "StringStream.h"

aesEncryptor::aesEncryptor(const std::string& key):
    _cipher(EVP_aes_256_gcm())
{
    _key = convertStringToChar(key);
}

aesEncryptor::~aesEncryptor()
{
    delete _key;
}

//ciphertext format="IV|CIPHER|AUH_TAG"
int aesEncryptor::gcmEncrypt(IStream* plainStream, unsigned char *key_buf, IStream* cipherStream)
{
    unsigned char iv[IV_LEN];
    unsigned char tag[AES_BLOCK_SIZE];
    unsigned char in_buf[BUF_SIZE];
    unsigned char out_buf[BUF_SIZE];

    EVP_CIPHER_CTX ctx;

    EVP_CIPHER_CTX_init(&ctx);
    RAND_bytes(iv, sizeof(iv));

    int ret = 0;
    ret = cipherStream->writeBuf(iv, sizeof(iv));
    if(ret != sizeof(iv)) 
    {
        std::cerr << "Failed to write IV" << std::endl;
        return -1;
    }

    ret = EVP_EncryptInit_ex(&ctx, _cipher, 0, _key, iv); 
    if(ret != 1)
    {
        std::cerr << "Failed to initialize encryptor" << std::endl;
        return -1;
    }

    int bytes_encrypted;
    size_t bytes_read;
    while((bytes_read = plainStream->readBuf(in_buf, BUF_SIZE)) > 0) 
    {
        ret = EVP_EncryptUpdate(&ctx, out_buf, &bytes_encrypted, in_buf, bytes_read);
        if(ret != 1)
        {
            std::cerr << "Failed to encrypt" << std::endl;
            return -1;
        }

        ret = cipherStream->writeBuf(out_buf, bytes_encrypted);
        if(ret != bytes_encrypted ) 
        {
            std::cerr << "Failed to write encrypted data" << std::endl;
            return -1;
        }
    }

    ret = EVP_EncryptFinal_ex(&ctx, out_buf, &bytes_encrypted);
    if(ret != 1) 
    {
        std::cerr << "Failed to finalize encryption" << std::endl;
        return -1;
    }

    if(bytes_encrypted != 0)
    {
        std::cerr << "Finalized unexpected " << bytes_encrypted << " bytes output" << std::endl;
        return -1;
    }

    ret = EVP_CIPHER_CTX_ctrl( &ctx, EVP_CTRL_GCM_GET_TAG, AES_BLOCK_SIZE, tag);
    if(ret != 1)
    {
        std::cerr << "Failed to get auth tag" << std::endl;
        return -1;
    }

    ret = cipherStream->writeBuf(tag, AES_BLOCK_SIZE);
    if(ret != AES_BLOCK_SIZE)
    {
        std::cerr << "Failed to write GCM tag" << std::endl;
        return -1;
    }

    return 0;
}

int aesEncryptor::gcmDecrypt(IStream* cipherStream, unsigned char *key_buf, IStream* plainStream)
{
    unsigned char iv[IV_LEN];
    unsigned char tag[AES_BLOCK_SIZE];
    unsigned char in_buf[BUF_SIZE];
    unsigned char out_buf[BUF_SIZE];

    EVP_CIPHER_CTX ctx;
    size_t bytes_read;
    int bytes_decrypted;

    unsigned int file_len = cipherStream->getSize();

    if(file_len < (AES_BLOCK_SIZE + IV_LEN + 1))
    {
        std::cerr << "Stream not long enough to be decrypted, streamSize=" << file_len << std::endl;
        return -1;
    }

    int ret = 0;

    ret = cipherStream->readBuf(iv, IV_LEN);
    if(ret != IV_LEN)
    {
        std::cerr << "Failed to read IV" << std::endl;
        printErrno();
        return -1;
    }
    file_len = file_len - IV_LEN;

    EVP_CIPHER_CTX_init(&ctx);

    ret = EVP_DecryptInit_ex(&ctx, _cipher, 0, key_buf, iv);
    if(ret != 1)
    {
        std::cerr << "Failed to initialize decryptor" << std::endl;
        return -1;
    }

    size_t to_read = file_len - AES_BLOCK_SIZE;
    while(to_read > 0)
    {
        bytes_read = cipherStream->readBuf(in_buf, std::min((size_t)BUF_SIZE, to_read));
        if(bytes_read != std::min((size_t)BUF_SIZE, to_read))
        {
            std::cerr << "Couldn't read file" << std::endl;
            return -1;
        }
        to_read -= bytes_read;

        ret = EVP_DecryptUpdate( &ctx, out_buf, &bytes_decrypted, in_buf, bytes_read );
        if(ret != 1)
        {
            std::cerr << "Failed to decrypt" << std::endl;
            return -1;
        }

        ret = plainStream->writeBuf(out_buf, bytes_decrypted);
        if(ret != bytes_decrypted)
        {
            std::cerr << "Couldn't write decrypted bytes" << std::endl;
            return -1;
        }
    }

    ret = cipherStream->readBuf(tag, AES_BLOCK_SIZE);
    if(ret != AES_BLOCK_SIZE)
    {
        std::cerr << "can't read auth tag" << std::endl;
        return -1;
    }

    // Check auth tag
    ret = EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, AES_BLOCK_SIZE, tag);
    if(ret != 1)
    {
        std::cerr << "Failed to initialize set auth tag" << std::endl;
        return -1;
    }

    ret = EVP_DecryptFinal(&ctx, out_buf, &bytes_decrypted);
    if(ret != 1)
    {
        std::cerr << "Failed to finalize decryptor" << std::endl;
        return -1;
    }

    if(bytes_decrypted != 0)
    {
        std::cerr << "Decrypt finalization returned extra stuff" << std::endl;
        return -1;
    }

    return 0;
}

std::string aesEncryptor::gcmEncryptString(const std::string& plain)
{
    StringStream plainStream;
    plainStream.addString(plain);

    StringStream cipherStream;
    int ret = gcmEncrypt(&plainStream, _key, &cipherStream);
    if(ret != 0)
    {
        std::cerr << "Encryption failed..." << std::endl;
    }
    return cipherStream.getString();
}

int aesEncryptor::gcmEncryptString(const std::string& plain, const char* cipherFile)
{
    StringStream inStream;
    inStream.addString(plain);

    FileStream cipherStream;
    cipherStream.openFile(cipherFile, O_CREAT | O_WRONLY | O_TRUNC);

    int ret = gcmEncrypt(&inStream, _key, &cipherStream);
    return ret;
}

int aesEncryptor::gcmEncryptFile(const char* plainFile, const char* cipherFile)
{
    FileStream inStream;
    inStream.openFile(plainFile, O_RDONLY);

    FileStream outStream;
    outStream.openFile(cipherFile, O_CREAT | O_WRONLY | O_TRUNC);

    int ret = gcmEncrypt(&inStream, _key, &outStream);
    return ret;
}

int aesEncryptor::gcmDecryptFile(const char* plainFile, const char* cipherFile)
{
    FileStream cipherStream;
    cipherStream.openFile(cipherFile, O_CREAT | O_RDONLY);

    FileStream plainStream;
    plainStream.openFile(plainFile,  O_CREAT | O_WRONLY | O_TRUNC);

    return gcmDecrypt(&cipherStream, _key, &plainStream);
}

std::string aesEncryptor::gcmDecryptString(const std::string& cipherString)
{
    StringStream cipherStream;
    cipherStream.addString(cipherString);

    StringStream plainStream;

    int ret = gcmDecrypt(&cipherStream, _key, &plainStream);
    if(ret != 0)
    {
        std::cerr << "Decryption failed..." << std::endl;
    }
    return plainStream.getString();
}
