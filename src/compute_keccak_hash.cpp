#include <iostream>
#include <string>
#include <cryptopp/keccak.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;

int main() {
    // Prompt the user to enter a string
    std::cout << "Enter the string to hash: ";
    std::string input;
    std::getline(std::cin, input);

    // This string will hold the resulting hash in hexadecimal format
    std::string output;

    // Create a Keccak-256 hash object
    Keccak_256 keccak;

    // Compute the hash: input -> hash filter -> hex encoder -> output string
    StringSource ss(input, true,
        new HashFilter(keccak,
            new HexEncoder(
                new StringSink(output)
            )
        )
    );

    // Output the computed hash
    std::cout << "Keccak-256 hash: " << output << std::endl;

    return 0;
}