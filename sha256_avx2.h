#ifndef SHA256_AVX2_H
#define SHA256_AVX2_H

// #include <cstdint>
#include <cstdint>
#include <cstddef>

void sha256avx2_8B(
    const uint8_t* data0, const uint8_t* data1, const uint8_t* data2, const uint8_t* data3,
    const uint8_t* data4, const uint8_t* data5, const uint8_t* data6, const uint8_t* data7,
    unsigned char* hash0, unsigned char* hash1, unsigned char* hash2, unsigned char* hash3,
    unsigned char* hash4, unsigned char* hash5, unsigned char* hash6, unsigned char* hash7
);

// ✅ NEW: Unified function untuk semua panjang input
void sha256avx2_8B_variable(
    const uint8_t* data0, const uint8_t* data1, const uint8_t* data2, const uint8_t* data3,
    const uint8_t* data4, const uint8_t* data5, const uint8_t* data6, const uint8_t* data7,
    size_t length, // 33 untuk compressed, 65 untuk uncompressed
    unsigned char* hash0, unsigned char* hash1, unsigned char* hash2, unsigned char* hash3,
    unsigned char* hash4, unsigned char* hash5, unsigned char* hash6, unsigned char* hash7
);

#endif // SHA256_AVX2_H

