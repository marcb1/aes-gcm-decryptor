#include "aesEncryptor.h"
#include "StringStream.h"
#include "FileStream.h"

int main(int argc, char** argv)
{
    std::string hashedKey = simpleSHA256("marcbassil");
    aesEncryptor e(hashedKey);
    std::string test("marc__DFSDbassilsdfsdwhodsftwwfuckack\n");
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

    {
        while(1)
        {
            std::cout << "-" << std::endl;
            std::string plain("M");
            std::string cipher = e.gcmEncryptString(plain);
            std::remove("file");
            std::ofstream a("file");
            a << cipher << std::flush;
            a.close();
//            std::string decrypted;
 //           e.gcmDecryptFiletoString("file", decrypted);
           // there's a bug here!
            std::cout << "AFTER HERE" << std::endl;
            StringStream s;
            FileStream f;
            s.addString(cipher);
            f.openFile("file", O_RDONLY);
            std::cout << "FILE " << f.getSize() << " String" << s.getSize() << std::endl;
            std::string get = s.getString();
            unsigned char test[20];
            f.readBuf(test, 19);
            std::string files = convertCharToString(test, 19);
            s.readBuf(test, 19);
            std::string strings = convertCharToString(test, 19);
            std::cout << "original" << string_to_hex(cipher) << std::endl;
            std::cout << "get" << string_to_hex(get) << std::endl;
            std::cout << string_to_hex(strings) << std::endl;
            std::cout << string_to_hex(files) << std::endl;

            std::string decrypted = e.gcmDecryptString(cipher);

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
