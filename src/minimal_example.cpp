#include <iostream>
#include <array>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

// This function encrypts and then decrypts a given plaintext using AES.
std::string encryptDecryptAES(const std::string &plaintext) {
    // Use std::array for the key (and IV in this case) for modern C++ safety.
    std::array<CryptoPP::byte, CryptoPP::AES::DEFAULT_KEYLENGTH> key = {0};

    // Encrypt the plaintext.
    std::string ciphertext;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor(key.data(), key.size(), key.data());
    CryptoPP::StringSource ss1(plaintext, true,
        new CryptoPP::StreamTransformationFilter(encryptor,
            new CryptoPP::StringSink(ciphertext)
        )
    );

    // Decrypt the ciphertext back to plaintext.
    std::string decryptedtext;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor(key.data(), key.size(), key.data());
    CryptoPP::StringSource ss2(ciphertext, true,
        new CryptoPP::StreamTransformationFilter(decryptor,
            new CryptoPP::StringSink(decryptedtext)
        )
    );

    return decryptedtext;
}

int main() {
    std::string message = "Hello, Crypto++ AES!";
    std::string result = encryptDecryptAES(message);
    std::cout << "Original:  " << message << "\n"
              << "Decrypted: " << result  << "\n";
    return 0;
}