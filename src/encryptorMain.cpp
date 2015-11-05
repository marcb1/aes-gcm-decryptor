#include "aesEncryptor.h"

int main(int argc, char** argv)
{
  if(argc != 5)
  {
    std::cout << "to encrypt: ./encryptor -e plaintext key ciphertext" << std::endl;
    std::cout << "to decrypt: ./encryptor -d decryptedtext key ciphertext" << std::endl;
    return 1;
  }

  std::string op(argv[1]);
  std::string plaintextFile(argv[2]);
  std::string userKey(argv[3]);
  std::string ciphertextFile(argv[4]);

  std::string hashedKey = simpleSHA256(userKey);
  aesEncryptor e(hashedKey);

  if(op == "-e")
  {
    e.gcmEncryptFile(plaintextFile.c_str(), ciphertextFile.c_str());
  }
  else if(op == "-d")
  {
    e.gcmDecryptFile(plaintextFile.c_str(), ciphertextFile.c_str());
  }
  else
  {
    std::cerr << "unknown operation; given=" << op << std::endl;
    return 1;
  }
  return 0;
}
