#include "aesEncryptor.h"
#include "StringStream.h"
#include "FileStream.h"

int main(int argc, char** argv)
{
    std::string hashedKey = simpleSHA256("marcbassil");
    aesEncryptor e(hashedKey);

    {
        while(1)
        {
            std::cout << "-" << std::endl;
            std::string plain("Marc bassil");
            std::string cipher = e.gcmEncryptString(plain);
            std::string decrypted = e.gcmDecryptString(cipher);

                assert(plain == decrypted);
                return 0;
        }
    }
    {
        std::cout << "-" << std::endl;
        std::string plain("Marc bassiloiugf yoeiurhyiodusufhky4roiulkfjhksjfhksyufhhewro8347y5riweuhrf123");
        std::string cipher = e.gcmEncryptString(plain);
        std::string decrypted = e.gcmDecryptString(cipher);

        if(plain != decrypted)
        {
            std::cout << decrypted << std::endl;
            assert(plain == decrypted);
        }
    }
    {
        std::cout << "-" << std::endl;
        std::string plain("Masflidslkfshy9pw8eurrrrd498r45duw4pruweofypiewuyfrdp9wa7eynro2ui49yrseic bassil 123");
        std::string cipher = e.gcmEncryptString(plain);
        std::string decrypted = e.gcmDecryptString(cipher);

        if(plain != decrypted)
        {
            std::cout << decrypted << std::endl;
            assert(plain == decrypted);
        }
    } 
    {
        std::cout << "-" << std::endl;
        std::string plain("Marc baldkshfslidufhyosiyrf948ruoieqwuyr08weyrfoiausdhflkashdfloawuyhrliaewury3al89yuerhwlkjefhlisdufhsfsdfssil 123");
        std::string cipher = e.gcmEncryptString(plain);
        std::string decrypted = e.gcmDecryptString(cipher);

        if(plain != decrypted)
        {
            std::cout << decrypted << std::endl;
            assert(plain == decrypted);
        }
    } 
    return 0;
}
