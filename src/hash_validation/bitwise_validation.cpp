// o1  generated

#include <iostream>
#include <string>

// Bitwise-based hex check.
// Explanation:
//   1) If '0' <= c <= '9', it's valid.
//   2) Otherwise, convert c to uppercase by clearing bit 5 (c & ~0x20).
//      Then check if 'A' <= (converted c) <= 'F'.
inline bool isValidHexChar(char c) {
    // Check numeric range.
    if (c >= '0' && c <= '9') {
        return true;
    }
    // Force uppercase by clearing bit 5 (0x20).
    unsigned char upperC = static_cast<unsigned char>(c) & static_cast<unsigned char>(~0x20);
    return (upperC >= 'A' && upperC <= 'F');
}

bool isKeccak256(const std::string& input) {
    // Copy input so we can remove optional "0x"/"0X" prefix without changing original.
    std::string str = input;

    // If input starts with "0x" or "0X", remove the prefix.
    if (str.size() >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        str = str.substr(2);
    }

    // A valid keccak256 hash must have exactly 64 hex characters.
    if (str.size() != 64) {
        return false;
    }

    // Check each character via bitwise function.
    for (char c : str) {
        if (!isValidHexChar(c)) {
            return false;
        }
    }
    return true;
}

int main() {
    std::string input;
    std::cout << "Enter a possible keccak256 hash: ";
    std::cin >> input;

    if (isKeccak256(input)) {
        std::cout << "The string is a valid keccak256 hash.\n";
    } else {
        std::cout << "The string is not a valid keccak256 hash.\n";
    }
    return 0;
}