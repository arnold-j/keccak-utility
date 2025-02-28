	#include <iostream>
#include <string>

// Helper function to check if a character is a valid hex digit.
bool isValidHexChar(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

// Function that checks if the given string is a valid keccak256 hash.
bool isKeccak256(const std::string& hexStr) {
    std::string str = hexStr;
    // If the string starts with "0x" or "0X", remove the prefix.
    if (str.size() >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        str = str.substr(2);
    }
    // A valid keccak256 hash must have exactly 64 hexadecimal characters.
    if (str.length() != 64)
        return false;
    // Check each character to ensure it is a valid hexadecimal digit.
    for (char c : str) {
        if (!isValidHexChar(c))
            return false;
    }
    return true;
}

int main() {
    std::string input;
    std::cout << "Enter hexadecimal string: ";
    std::cin >> input;

    if (isKeccak256(input))
        std::cout << "The string is a valid keccak256 hash." << std::endl;
    else
        std::cout << "The string is not a valid keccak256 hash." << std::endl;

    return 0;
}