// o1 generated

// PSEUDO-CODE METAL kernel (not standard C++)
#include <metal_stdlib>
using namespace metal;

// Suppose each thread checks one string. 
// stringData is a buffer containing all strings back-to-back.
// results is a buffer of booleans.

kernel void validateHexStrings(device const char* stringData,
                               device bool* results,
                               uint numStrings,
                               uint stridePerString, // how many chars to skip per string
                               uint2 tid [[thread_position_in_grid]])
{
    uint idx = tid.x; // which string to process
    if (idx >= numStrings) return;

    // Compute start offset of string in 'stringData'
    uint start = idx * stridePerString;

    bool isValid = true;
    // For example, we assume 64 hex digits (like keccak256) + optional prefix logic.
    // You’d do the same checks here, but in parallel for many strings.
    for (uint i = 0; i < 64; ++i) {
        char c = stringData[start + i];
        // Validate with bitwise or LUT logic
        if (!isValidHexChar(c)) {
            isValid = false;
            break;
        }
    }
    // Write result
    results[idx] = isValid;
}