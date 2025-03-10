#include <memory>
#include <stdexcept>
#include <secp256k1.h>

// Custom deleter for the secp256k1 context
struct Secp256k1Deleter {
    void operator()(secp256k1_context* ctx) const noexcept {
        if (ctx) {
            secp256k1_context_destroy(ctx);
        }
    }
};

// RAII wrapper for secp256k1_context using std::unique_ptr
class Secp256k1Context {
public:
    // Constructor acquires the secp256k1 context with specified flags.
    explicit Secp256k1Context(unsigned int flags)
        : ctx_(secp256k1_context_create(flags)) {
        if (!ctx_) {
            throw std::runtime_error("Failed to create secp256k1 context");
        }
    }

    // Overload operator-> for direct pointer access.
    secp256k1_context* operator->() const noexcept {
        return ctx_.get();
    }

    // Provide access to the underlying raw pointer.
    secp256k1_context* get() const noexcept { return ctx_.get(); }

    // Deleted copy constructor and copy assignment operator to prevent copying.
    Secp256k1Context(const Secp256k1Context&) = delete;
    Secp256k1Context& operator=(const Secp256k1Context&) = delete;

    // Default move constructor and move assignment operator suffice.
    Secp256k1Context(Secp256k1Context&&) noexcept = default;
    Secp256k1Context& operator=(Secp256k1Context&&) noexcept = default;

    // Optional swap method for efficient resource exchange.
    void swap(Secp256k1Context& other) noexcept {
        ctx_.swap(other.ctx_);
    }

    // Optional conversion operator to secp256k1_context* for seamless integration.
    operator secp256k1_context*() const noexcept {
        return ctx_.get();
    }

private:
    std::unique_ptr<secp256k1_context, Secp256k1Deleter> ctx_;
};

/**
 * 
 * simple terminal program structure similar to function found in standalone file.
 * 

#include <iostream>
#include <secp256k1.h>

int main() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        std::cerr << "Failed to create secp256k1 context" << std::endl;
        return 1;
    }

    // Perform cryptographic operations with ctx...

    secp256k1_context_destroy(ctx);
    return 0;
}

**/