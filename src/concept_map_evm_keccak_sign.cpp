// example concept mapping of evm_keccak_sign.cpp
// by ChatGPT 4o

// PrivateKey.h
#ifndef PRIVATE_KEY_H
#define PRIVATE_KEY_H

#include <vector>
#include <optional>
#include <secp256k1.h>
#include "Secp256k1Context.h"

class PrivateKey {
public:
    static std::optional<std::vector<unsigned char>> Generate(const Secp256k1Context& ctx);
};

#endif // PRIVATE_KEY_H

// PrivateKey.cpp
#include "PrivateKey.h"
#include <osrng.h>
#include <iostream>

std::optional<std::vector<unsigned char>> PrivateKey::Generate(const Secp256k1Context& ctx) {
    AutoSeededRandomPool rng;
    std::vector<unsigned char> privateKey(32);

    for (int attempts = 0; attempts < 10; ++attempts) {
        rng.GenerateBlock(privateKey.data(), privateKey.size());
        if (secp256k1_ec_seckey_verify(ctx.get(), privateKey.data())) {
            return privateKey;
        }
    }
    std::cerr << "Failed to generate valid private key after multiple attempts" << std::endl;
    return std::nullopt;
}

// PublicKey.h
#ifndef PUBLIC_KEY_H
#define PUBLIC_KEY_H

#include <vector>
#include <optional>
#include <secp256k1.h>
#include "Secp256k1Context.h"

class PublicKey {
public:
    static std::optional<std::vector<unsigned char>> Derive(const Secp256k1Context& ctx, const std::vector<unsigned char>& privateKey);
};

#endif // PUBLIC_KEY_H

// PublicKey.cpp
#include "PublicKey.h"
#include <iostream>

std::optional<std::vector<unsigned char>> PublicKey::Derive(const Secp256k1Context& ctx, const std::vector<unsigned char>& privateKey) {
    if (privateKey.size() != 32) {
        std::cerr << "Invalid private key length" << std::endl;
        return std::nullopt;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx.get(), &pubkey, privateKey.data())) {
        std::cerr << "Failed to create public key" << std::endl;
        return std::nullopt;
    }

    std::vector<unsigned char> serializedPubKey(65);
    size_t outputLen = 65;
    secp256k1_ec_pubkey_serialize(ctx.get(), serializedPubKey.data(), &outputLen, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    return serializedPubKey;
}

// Signature.h
#ifndef SIGNATURE_H
#define SIGNATURE_H

#include <vector>
#include <optional>
#include <secp256k1.h>
#include "Secp256k1Context.h"

class Signature {
public:
    static std::optional<std::vector<unsigned char>> Sign(const Secp256k1Context& ctx, const std::vector<unsigned char>& privateKey, const std::vector<unsigned char>& messageHash);
};

#endif // SIGNATURE_H

// Signature.cpp
#include "Signature.h"
#include <iostream>

std::optional<std::vector<unsigned char>> Signature::Sign(const Secp256k1Context& ctx, const std::vector<unsigned char>& privateKey, const std::vector<unsigned char>& messageHash) {
    if (privateKey.size() != 32 || messageHash.size() != 32) {
        std::cerr << "Invalid private key or message hash length" << std::endl;
        return std::nullopt;
    }

    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_sign_recoverable(ctx.get(), &sig, messageHash.data(), privateKey.data(), nullptr, nullptr)) {
        std::cerr << "Failed to sign message" << std::endl;
        return std::nullopt;
    }

    std::vector<unsigned char> signature(65);
    int recId;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx.get(), signature.data(), &recId, &sig);
    signature[64] = static_cast<unsigned char>(recId + 27);

    return signature;
}
