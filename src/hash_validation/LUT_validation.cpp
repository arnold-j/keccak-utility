// o1 generated

#include <iostream>
#include <string>

// The table for 256 possible chars: 'true' = hex valid, 'false' = invalid.
static bool isHexTable[256];

inline bool isValidHexChar(char c) {
    return isHexTable[static_cast<unsigned char>(c)];
}

// Build a lookup table to flag whether a char is hex-valid:
static bool buildHexLookupTable() {
    // We fill a static array once. 
    // indexed by unsigned char [0..255].
    for (int i = 0; i < 256; ++i) {
        unsigned char c = static_cast<unsigned char>(i);
        // valid if 0..9 or (A..F) or (a..f)
        bool digit   = (c >= '0' && c <= '9');
        bool lowerAF = (c >= 'a' && c <= 'f');
        bool upperAF = (c >= 'A' && c <= 'F');
        isHexTable[i] = (digit || lowerAF || upperAF);
    }
    return true;
}

static bool isHexTableInitialized = buildHexLookupTable();

bool isKeccak256(const std::string& input) {
    std::string str = input;
    // Strip prefix if present
    if (str.size() >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        str = str.substr(2);
    }
    // Must be exactly 64 hex digits
    if (str.size() != 64) {
        return false;
    }
    // Check each char in the table
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