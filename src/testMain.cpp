#include "aesEncryptor.h"
#include "StringStream.h"
#include "FileStream.h"

int main(int argc, char** argv)
{
    std::string hashedKey = simpleSHA256("marcbassil");

    {
        aesEncryptor e(hashedKey);
        std::string plain("Marc");
        std::string cipher = e.gcmEncryptString(plain);
        std::string decrypted = e.gcmDecryptString(cipher);

        assert(plain == decrypted);
    }
    {
        aesEncryptor e(hashedKey);
        std::string plain("M");
        std::string cipher = e.gcmEncryptString(plain);
        std::string decrypted = e.gcmDecryptString(cipher);

        assert(plain == decrypted);
    }
    {
        aesEncryptor e(hashedKey);
        std::string plain("Mfiudhfyo97yrofnidsuhfo983nuofiusf\n\n\n\fdsjghsdkfhgkf78sdfkjhwgekf8w7egfuhd\n\n\0sdkfjgsdfjgsdkfu\0\0\0\0");
        std::string cipher = e.gcmEncryptString(plain);
        std::string decrypted = e.gcmDecryptString(cipher);

        assert(plain == decrypted);
    }     
    {
        aesEncryptor e(hashedKey);
        std::string plain("Marc 2346824   dj");
        std::string cipher = e.gcmEncryptString(plain);
        std::string decrypted = e.gcmDecryptString(cipher);

        assert(plain == decrypted);
    } 
    {
        aesEncryptor e(hashedKey);
        std::string cipherFile = "/tmp/test_file";
        std::string plain = "testkl jdfh ksjdfh\0\0\0\0\0\0\0\0\0\n\n\n\n\n\ndfgdfgdfg\0\0\0\0dsfsdf\n\n\n\n";
        int ret = e.gcmEncryptStringtoFile(plain, cipherFile);
        assert(ret == 0);
        std::string decrypted;
        ret = e.gcmDecryptFiletoString(cipherFile, decrypted);
        assert(plain == decrypted);
    }
    return 0;
}
