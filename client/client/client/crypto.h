#pragma once
#include <cryptopp/rsa.h>
#include <string>
#include <cryptopp/base64.h>

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include "crypto.h"
#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>
#include <cryptopp/oaep.h>



class CryptoManager {
public:
    CryptoManager();
    std::string getPublicKey() const;
    std::string decryptWithRSA(const std::string& encryptedData) const;
    std::string exportPrivateKey() const;
    void importPrivateKey(const std::string& encodedKey);
    std::string encryptWithAES(const std::string& data, const std::string& aesKey);

private:
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::RSA::PublicKey publicKey;
};