#include <iostream>
#include <vector>
#include <array>
#include <stdexcept>
#include <cctype>
#include <algorithm>
#include <string_view>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstring>
#include <cryptopp/keccak.h>

namespace eth {

    using Byte = unsigned char;

    /**
     * @brief Convert a vector of bytes to a hexadecimal string using a fixed-size buffer.
     * @param bytes Input bytes.
     * @param hexBuffer Pre-allocated buffer to store the hex string (must be at least 2*bytes.size() + 1 bytes).
     * @note This function is noexcept as it does not throw exceptions.
     */
    inline void bytesToHex(const std::vector<Byte>& bytes, char* hexBuffer) noexcept {
        constexpr char hexDigits[] = "0123456789abcdef";
        const Byte* bytePtr = bytes.data();
        char* hexPtr = hexBuffer;
        for (size_t i = 0; i < bytes.size(); ++i) {
            Byte b = bytePtr[i];
            *hexPtr++ = hexDigits[(b >> 4) & 0x0F];
            *hexPtr++ = hexDigits[b & 0x0F];
        }
        *hexPtr = '\0'; // Null-terminate the string
    }

    /**
     * @brief Convert a hexadecimal string to a vector of bytes using a lookup table.
     * @param hex The hex string.
     * @return std::vector<Byte> Parsed bytes.
     * @throws std::runtime_error if the input is invalid.
     */
    inline std::vector<Byte> hexToBytes(std::string_view hex) {
        if (hex.size() % 2 != 0) {
            throw std::runtime_error("Hex string has odd length.");
        }
        // Lookup table for hex digit conversion (0-15)
        constexpr std::array<int, 256> hexLookup = []() constexpr {
            std::array<int, 256> table{};
            for (int i = 0; i < 256; ++i) table[i] = -1; // Invalid by default
            for (int i = '0'; i <= '9'; ++i) table[i] = i - '0';
            for (int i = 'a'; i <= 'f'; ++i) table[i] = i - 'a' + 10;
            for (int i = 'A'; i <= 'F'; ++i) table[i] = i - 'A' + 10;
            return table;
        }();

        std::vector<Byte> bytes;
        bytes.reserve(hex.size() / 2);
        const char* hexData = hex.data();
        for (size_t i = 0; i < hex.size(); i += 2) {
            char high = hexData[i];
            char low = hexData[i + 1];
            int highValue = hexLookup[static_cast<unsigned char>(high)];
            int lowValue = hexLookup[static_cast<unsigned char>(low)];
            if (highValue == -1 || lowValue == -1) {
                throw std::runtime_error("Hex string contains invalid characters.");
            }
            bytes.push_back(static_cast<Byte>((highValue << 4) | lowValue));
        }
        return bytes;
    }

    /**
     * @brief Apply EIP-55 checksum encoding to an Ethereum address in-place.
     * @param addressBuffer Buffer containing the address (must be 42 bytes, starting with "0x").
     * @param keccak Reusable Keccak-256 hash object.
     * @throws std::runtime_error if the address format is invalid.
     */
    inline void toEIP55Address(char* addressBuffer, CryptoPP::Keccak_256& keccak) {
        if (std::strlen(addressBuffer) != 42 || addressBuffer[0] != '0' || addressBuffer[1] != 'x') {
            throw std::runtime_error("Invalid address format for EIP-55 encoding");
        }
        // Create a lowercase copy (40 hex characters + null terminator)
        char addrLower[41];
        std::strncpy(addrLower, addressBuffer + 2, 40);
        addrLower[40] = '\0';
        std::transform(addrLower, addrLower + 40, addrLower, ::tolower);

        std::array<Byte, CryptoPP::Keccak_256::DIGESTSIZE> hash{};
        keccak.Restart();
        keccak.Update(reinterpret_cast<const Byte*>(addrLower), 40);
        keccak.Final(hash.data());

        // Apply checksum in-place using the hash nibbles
        for (size_t i = 0; i < 40; ++i) {
            size_t byteIndex = i / 2;
            bool isHighNibble = (i % 2) == 0;
            int hashNibble = isHighNibble ? (hash[byteIndex] >> 4) & 0x0F : hash[byteIndex] & 0x0F;
            if (hashNibble >= 8) {
                addressBuffer[i + 2] = std::toupper(addressBuffer[i + 2]);
            } else {
                addressBuffer[i + 2] = std::tolower(addressBuffer[i + 2]);
            }
        }
    }

    /**
     * @brief Derive an Ethereum address from an uncompressed public key.
     * @param publicKey The uncompressed public key.
     * @param addressBuffer Buffer to store the resulting address (must be 43 bytes, including "0x" and null terminator).
     * @param keccak Reusable Keccak-256 hash object.
     * @throws std::runtime_error if the public key size is incorrect.
     */
    inline void deriveEthereumAddress(const std::vector<Byte>& publicKey, char* addressBuffer, CryptoPP::Keccak_256& keccak) {
        if (publicKey.size() != 64) {
            throw std::runtime_error("Invalid public key size. Expected 64 bytes.");
        }
        std::array<Byte, CryptoPP::Keccak_256::DIGESTSIZE> hash{};
        keccak.Restart();
        keccak.Update(publicKey.data(), publicKey.size());
        keccak.Final(hash.data());

        std::vector<Byte> addressBytes(hash.end() - 20, hash.end());
        addressBuffer[0] = '0';
        addressBuffer[1] = 'x';
        bytesToHex(addressBytes, addressBuffer + 2);
        toEIP55Address(addressBuffer, keccak);
    }

    /**
     * @brief Parse command-line arguments for public key input.
     * @param argc Argument count.
     * @param argv Argument vector.
     * @return std::vector<Byte> The parsed public key.
     * @throws std::runtime_error if the input is invalid.
     */
    inline std::vector<Byte> parsePublicKey(int argc, char* argv[]) {
        std::vector<Byte> publicKey;
        if (argc == 2) {
            std::string_view hexInput = argv[1];
            if (hexInput.length() != 128) {
                throw std::runtime_error("Invalid hex input length. Expected 128 characters (64 bytes).");
            }
            publicKey = hexToBytes(hexInput);
        } else {
            std::cout << "No public key provided. Using default test data.\n";
            publicKey = {
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
                0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
                0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f, 0x2a, 0x2b, 0x2c, 0x2d
            };
        }
        return publicKey;
    }

    /**
     * @brief Derive multiple Ethereum addresses in parallel.
     * @param publicKeys Vector of public keys.
     * @param addresses Vector of buffers to store the resulting addresses (each must be 43 bytes).
     * @throws std::runtime_error if the number of public keys and address buffers do not match.
     */
    inline void deriveMultipleAddresses(const std::vector<std::vector<Byte>>& publicKeys,
                                          std::vector<std::array<char, 43>>& addresses) {
        if (publicKeys.size() != addresses.size()) {
            throw std::runtime_error("Number of public keys and address buffers must match.");
        }
        const size_t numKeys = publicKeys.size();
        std::atomic<size_t> index{0};
        const size_t numThreads = std::max<size_t>(1, std::thread::hardware_concurrency());
        std::vector<std::thread> threads;
        threads.reserve(numThreads);
        auto worker = [&]() {
            CryptoPP::Keccak_256 keccak;
            while (true) {
                size_t i = index.fetch_add(1, std::memory_order_relaxed);
                if (i >= numKeys)
                    break;
                deriveEthereumAddress(publicKeys[i], addresses[i].data(), keccak);
            }
        };
        for (size_t t = 0; t < numThreads; ++t) {
            threads.emplace_back(worker);
        }
        for (auto& t : threads) {
            t.join();
        }
    }

} // namespace eth

int main(int argc, char* argv[]) {
    try {
        // Example: Derive a single address
        auto publicKey = eth::parsePublicKey(argc, argv);
        char addressBuffer[43];
        CryptoPP::Keccak_256 keccak;
        eth::deriveEthereumAddress(publicKey, addressBuffer, keccak);
        std::cout << "Derived Ethereum address: " << addressBuffer << '\n';

        // Example: Derive multiple addresses in parallel.
        // For demonstration, we duplicate the same public key.
        std::vector<std::vector<eth::Byte>> publicKeys = { publicKey, publicKey };
        std::vector<std::array<char, 43>> addresses(publicKeys.size());
        eth::deriveMultipleAddresses(publicKeys, addresses);
        for (const auto& addr : addresses) {
            std::cout << "Derived Ethereum address (parallel): " << addr.data() << '\n';
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
    return 0;
}