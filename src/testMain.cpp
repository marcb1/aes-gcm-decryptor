#include "aesEncryptor.h"
#include "StringStream.h"
#include "FileStream.h"

int main(int argc, char** argv)
{
    std::string hashedKey = simpleSHA256("marcbassil");
    aesEncryptor e(hashedKey);
#ifdef FUCK
    std::string test("marc__DFSDbassilsdfsdwhodsftwwfuckack");
    StringStream s;
    s.addString(test);
    FileStream a;
    a.openFile("./test", O_RDONLY);
    std::cout << a.getSize() << "|" << s.getSize() << std::endl;
    unsigned char marc[10];
    a.readBuf(marc, 19);
    std::cout << marc << "|" << std::endl;
    s.readBuf(marc, 19);
    std::cout << marc << "|" << std::endl;
    a.readBuf(marc, 5);
    std::cout << marc << "|" << std::endl;
    s.readBuf(marc, 5);
    std::cout << marc << "|" << std::endl;
    a.readBuf(marc, 2);
    std::cout << marc << "|" << std::endl;
    s.readBuf(marc, 2);
    std::cout << marc << "|" << std::endl;
    a.readBuf(marc, 2);
    std::cout << marc << "|" << std::endl;
    s.readBuf(marc, 2);
    std::cout << marc << "|" << std::endl;
    a.readBuf(marc, 2);
    std::cout << marc << "|" << std::endl;
    s.readBuf(marc, 2);
    std::cout << marc << "|" << std::endl;
    a.readBuf(marc, 2);
    std::cout << marc << "|" << std::endl;
    s.readBuf(marc, 2);
    std::cout << marc << "|" << std::endl;
    a.readBuf(marc, 20);
    std::cout << marc << "|" << std::endl;
    s.readBuf(marc, 20);
    std::cout << marc << "|" << std::endl;
    std::cout << "MARC" << std::endl;
#endif

    {
        while(1)
        {
            std::cout << "-" << std::endl;
            std::string plain("Marc bassil 123dsfkjjjjjjjjjsdkjjhhhhhhhhhhhhhhhhh");
            std::string cipher = e.gcmEncryptString(plain);
            std::remove("file");
            std::ofstream a("file");
            a << cipher << std::flush;
            a.close();
            std::string decrypted;
            e.gcmDecryptFiletoString("file", decrypted);
           // there's a bug here!
            std::cout << "AFTER HERE" << std::endl;
            decrypted = e.gcmDecryptString(cipher);

                assert(plain == decrypted);
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
