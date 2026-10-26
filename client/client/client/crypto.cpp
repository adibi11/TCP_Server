
#include "crypto.h"

#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <cryptopp/queue.h>
#include <stdexcept>
//This module uses the Crypto++ library for cryptographic operations, including RSA and AES encryption/decryption.
//It was installed via vcpkg, and the include paths are set up to use the headers from the vcpkg installation directory.
CryptoManager::CryptoManager() {
	// Generate a new RSA key pair
    CryptoPP::AutoSeededRandomPool rng;
    privateKey.GenerateRandomWithKeySize(rng, 1024);
    publicKey.AssignFrom(privateKey);
}

// Export the public key in DER format
std::string CryptoManager::getPublicKey() const {
    CryptoPP::ByteQueue queue;
    publicKey.DEREncode(queue);

    std::string result(queue.CurrentSize(), '\0');
    queue.Get(reinterpret_cast<CryptoPP::byte*>(result.data()), result.size());

    return result;
}

//Decrypt the data with the private key to store later in the relevant files
std::string CryptoManager::decryptWithRSA(const std::string& encryptedData) const {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

    std::string decrypted;

    CryptoPP::StringSource source(
        encryptedData,
        true,
        new CryptoPP::PK_DecryptorFilter(
            rng,
            decryptor,
            new CryptoPP::StringSink(decrypted)
        )
    );

    return decrypted;
}

//Export the private key in DER format
std::string CryptoManager::exportPrivateKey() const {
    CryptoPP::ByteQueue queue;
    privateKey.DEREncode(queue);

    std::string encoded;
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded), false);

    queue.CopyTo(encoder);
    encoder.MessageEnd();

    return encoded;
}

//Import the private key to the client runtime
void CryptoManager::importPrivateKey(const std::string& encodedKey) {
    std::string decoded;

    CryptoPP::StringSource source(
        encodedKey,
        true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(decoded)
        )
    );

    CryptoPP::ByteQueue queue;
    queue.Put(reinterpret_cast<const CryptoPP::byte*>(decoded.data()), decoded.size());

    CryptoPP::RSA::PrivateKey loadedKey;
    loadedKey.BERDecode(queue);

    CryptoPP::AutoSeededRandomPool rng;
    if (!loadedKey.Validate(rng, 3))
        throw std::runtime_error("Invalid RSA private key");

    privateKey = loadedKey;
    publicKey.AssignFrom(privateKey);
}

//Encrypts with the AES key received by the server
std::string CryptoManager::encryptWithAES(const std::string& data, const std::string& aesKey) {
    if (aesKey.size() != CryptoPP::AES::DEFAULT_KEYLENGTH * 2)
        throw std::runtime_error("Invalid AES key size");

    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = {};

    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(
        reinterpret_cast<const CryptoPP::byte*>(aesKey.data()),
        aesKey.size(),
        iv
    );

    std::string encrypted;

    CryptoPP::StringSource source(
        data,
        true,
        new CryptoPP::StreamTransformationFilter(
            encryptor,
            new CryptoPP::StringSink(encrypted),
            CryptoPP::StreamTransformationFilter::PKCS_PADDING
        )
    );

    return encrypted;
}
