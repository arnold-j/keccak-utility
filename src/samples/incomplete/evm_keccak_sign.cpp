// currently "incomplete" file.

#include <iostream>
#include <optional>
#include <vector>
#include <string_view>
#include <cryptlib.h>
#include <osrng.h>
#include <eccrypto.h>
#include <keccak.h>
#include <hex.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

using namespace CryptoPP;

// RAII wrapper for secp256k1_context
class Secp256k1Context {
public:
    Secp256k1Context(unsigned int flags) {
        ctx_ = secp256k1_context_create(flags);
        if (!ctx_) {
            throw std::runtime_error("Failed to create secp256k1 context");
        }
    }

    ~Secp256k1Context() {
        secp256k1_context_destroy(ctx_);
    }

    secp256k1_context* get() const { return ctx_; }

private:
    secp256k1_context* ctx_;
};

// Convert bytes to hex string
std::string BytesToHex(const std::vector<byte>& data) {
    std::string hex;
    HexEncoder encoder(new StringSink(hex));
    encoder.Put(data.data(), data.size());
    encoder.MessageEnd();
    return hex;
}

// Hash a message using Keccak-256
std::vector<byte> Keccak256(std::string_view message) {
    Keccak_256 hash;
    std::vector<byte> digest(32);
    hash.CalculateDigest(digest.data(), reinterpret_cast<const byte*>(message.data()), message.size());
    return digest;
}

// Generate a secp256k1 private key
std::optional<std::vector<byte>> GeneratePrivateKey(const Secp256k1Context& ctx) {
    AutoSeededRandomPool rng;
    std::vector<byte> privateKey(32);

    for (int attempts = 0; attempts < 10; ++attempts) {
        rng.GenerateBlock(privateKey.data(), privateKey.size());
        if (secp256k1_ec_seckey_verify(ctx.get(), privateKey.data())) {
            return privateKey;
        }
    }
    std::cerr << "Failed to generate valid private key after multiple attempts" << std::endl;
    return std::nullopt;
}

/**
 * @brief Derive an uncompressed SECP256K1 public key from a 32-byte private key.
 *
 * @param ctx          An initialized Secp256k1Context for performing secp256k1 operations.
 * @param privateKey   A vector of exactly 32 bytes representing the private key.
 *
 * @return A 65-byte uncompressed public key on success; std::nullopt on failure.
 */
std::optional<std::vector<byte>> GetPublicKey(const Secp256k1Context& ctx, const std::vector<byte>& privateKey) {
    // Check that the private key is the correct size (32 bytes for secp256k1).
    if (privateKey.size() != 32) {
        std::cerr << "Invalid private key length" << std::endl;
        return std::nullopt;
    }

    // Prepare a secp256k1_pubkey structure. We'll fill this via the library call below.
    secp256k1_pubkey pubkey;

    // Attempt to create a pubkey from the private key; returns false on failure.
    if (!secp256k1_ec_pubkey_create(ctx.get(), &pubkey, privateKey.data())) {
        std::cerr << "Failed to create public key" << std::endl;
        return std::nullopt;
    }

    // An uncompressed SECP256K1 public key is 65 bytes: 
    //  1 byte for the 0x04 prefix 
    //  32 bytes for the X coordinate
    //  32 bytes for the Y coordinate
    std::vector<byte> serializedPubKey(65);
    size_t outputLen = 65;

    // Serialize the pubkey in uncompressed format into 'serializedPubKey'.
    secp256k1_ec_pubkey_serialize(ctx.get(), serializedPubKey.data(), &outputLen, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    // Return the serialized (uncompressed) public key.
    return serializedPubKey;
}

// Sign a hashed message using secp256k1
std::optional<std::vector<byte>> SignMessage(const Secp256k1Context& ctx, const std::vector<byte>& privateKey, const std::vector<byte>& messageHash) {
    if (privateKey.size() != 32 || messageHash.size() != 32) {
        std::cerr << "Invalid private key or message hash length" << std::endl;
        return std::nullopt;
    }

    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_sign_recoverable(ctx.get(), &sig, messageHash.data(), privateKey.data(), nullptr, nullptr)) {
        std::cerr << "Failed to sign message" << std::endl;
        return std::nullopt;
    }

    std::vector<byte> signature(65); // 64 bytes + 1 byte for recovery ID
    int recId;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx.get(), signature.data(), &recId, &sig);
    signature[64] = static_cast<byte>(recId + 27); // Ethereum adds 27 to recovery ID

    return signature;
}

// Verify a signature by recovering the public key
std::optional<std::vector<byte>> RecoverPublicKey(const Secp256k1Context& ctx, const std::vector<byte>& signature, const std::vector<byte>& messageHash) {
    if (signature.size() != 65 || messageHash.size() != 32) {
        std::cerr << "Invalid signature or message hash length" << std::endl;
        return std::nullopt;
    }

    secp256k1_ecdsa_recoverable_signature sig;
    int recId = signature[64] - 27;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx.get(), &sig, signature.data(), recId)) {
        std::cerr << "Invalid signature format" << std::endl;
        return std::nullopt;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ecdsa_recover(ctx.get(), &pubkey, &sig, messageHash.data())) {
        std::cerr << "Failed to recover public key" << std::endl;
        return std::nullopt;
    }

    std::vector<byte> serializedPubKey(65);
    size_t outputLen = 65;
    secp256k1_ec_pubkey_serialize(ctx.get(), serializedPubKey.data(), &outputLen, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    return serializedPubKey;
}

int main() {
    try {
        // Initialize secp256k1 context with RAII
        Secp256k1Context ctx(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

        // Generate key pair
        auto privateKey = GeneratePrivateKey(ctx);
        if (!privateKey) {
            return 1;
        }
        auto publicKey = GetPublicKey(ctx, *privateKey);
        if (!publicKey) {
            return 1;
        }

        std::cout << "Private Key: " << BytesToHex(*privateKey) << std::endl;
        std::cout << "Public Key: " << BytesToHex(*publicKey) << std::endl;

        // Message to sign
        std::string message = "EVM Keccak Signing Test";
        auto messageHash = Keccak256(message);

        std::cout << "Message Hash (Keccak-256): " << BytesToHex(messageHash) << std::endl;

        // Sign the message
        auto signature = SignMessage(ctx, *privateKey, messageHash);
        if (!signature) {
            return 1;
        }
        std::cout << "Signature: " << BytesToHex(*signature) << std::endl;

        // Recover public key from signature
        auto recoveredPubKey = RecoverPublicKey(ctx, *signature, messageHash);
        if (!recoveredPubKey) {
            return 1;
        }
        std::cout << "Recovered Public Key: " << BytesToHex(*recoveredPubKey) << std::endl;

        // Verify that the recovered public key matches the original
        if (*publicKey == *recoveredPubKey) {
            std::cout << "Signature is valid and public key matches!" << std::endl;
        } else {
            std::cout << "Signature verification failed!" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}