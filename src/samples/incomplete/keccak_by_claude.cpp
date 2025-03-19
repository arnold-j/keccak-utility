// keccak.h - Core Keccak definitions and declarations
#ifndef KECCAK_H
#define KECCAK_H

#include <cstdint>
#include <array>
#include <vector>

// Keccak-f[1600] state size in bytes (200 bytes = 1600 bits)
constexpr size_t KECCAK_STATE_SIZE = 200;

// Round constants for Keccak-f permutation
constexpr std::array<uint64_t, 24> KECCAK_ROUND_CONSTANTS = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

// Rotation offsets for Keccak-f permutation
constexpr std::array<int, 25> KECCAK_ROTATION_OFFSETS = {
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
    25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
};

class KeccakState {
private:
    // State as 5x5 array of 64-bit words
    std::array<uint64_t, 25> state;

public:
    KeccakState();
    
    // Reset state to all zeros
    void reset();
    
    // Apply Keccak-f[1600] permutation
    void permute();
    
    // Absorb data into the state
    void absorb(const uint8_t* data, size_t length, size_t rate);
    
    // Squeeze output from the state
    void squeeze(uint8_t* output, size_t length, size_t rate);
    
    // XOR data into state at specified offset
    void xorIntoState(const uint8_t* data, size_t length, size_t offset);
    
    // Extract bytes from state
    void extractBytes(uint8_t* output, size_t length, size_t offset) const;
};

// SHA3 hash functions
std::vector<uint8_t> sha3_224(const uint8_t* data, size_t length);
std::vector<uint8_t> sha3_256(const uint8_t* data, size_t length);
std::vector<uint8_t> sha3_384(const uint8_t* data, size_t length);
std::vector<uint8_t> sha3_512(const uint8_t* data, size_t length);

// SHAKE extendable output functions
std::vector<uint8_t> shake128(const uint8_t* data, size_t dataLength, size_t outputLength);
std::vector<uint8_t> shake256(const uint8_t* data, size_t dataLength, size_t outputLength);

#endif // KECCAK_H
