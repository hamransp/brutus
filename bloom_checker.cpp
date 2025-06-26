#include "bloom_checker.h"
#include <iostream>
#include <fstream>
#include <unordered_set>
#include <string>
#include <cstring>
#include <cstdint>
#include <array>
#include <cstdio>
#include <memory>
#include <vector>

// OPTIMASI 1: Precomputed lookup table untuk hex conversion
static uint8_t hex_lookup[256];
static bool lookup_initialized = false;

// Initialize hex lookup table
static void init_hex_lookup() {
    if (lookup_initialized) return;
    
    // Initialize all to 0 (invalid will be handled by caller)
    std::memset(hex_lookup, 0, 256);
    
    // Set valid hex characters
    for (int i = 0; i <= 9; i++) {
        hex_lookup['0' + i] = i;
    }
    for (int i = 0; i < 6; i++) {
        hex_lookup['A' + i] = 10 + i;
        hex_lookup['a' + i] = 10 + i;
    }
    
    lookup_initialized = true;
}

// OPTIMASI 2: Custom hash yang lebih cepat untuk array<uint8_t, 20>
struct OptimizedHash160Hash {
    std::size_t operator()(const std::array<uint8_t, 20>& arr) const noexcept {
        // OPTIMASI: Unroll loop + process 8 bytes at time using uint64_t
        const uint64_t* data64 = reinterpret_cast<const uint64_t*>(arr.data());
        
        // FNV-1a hash optimized untuk 20 bytes
        constexpr uint64_t FNV_PRIME = 0x100000001b3ULL;
        uint64_t hash = 0xcbf29ce484222325ULL;
        
        // Process first 16 bytes as 2x uint64_t
        hash = (hash ^ data64[0]) * FNV_PRIME;
        hash = (hash ^ data64[1]) * FNV_PRIME;
        
        // Process remaining 4 bytes
        const uint32_t* data32 = reinterpret_cast<const uint32_t*>(arr.data() + 16);
        hash = (hash ^ *data32) * FNV_PRIME;
        
        return hash;
    }
};

// OPTIMASI 3: Faster equality comparison
struct OptimizedHash160Equal {
    bool operator()(const std::array<uint8_t, 20>& a, 
                    const std::array<uint8_t, 20>& b) const noexcept {
        // OPTIMASI: Compare as uint64_t instead of byte by byte
        const uint64_t* a64 = reinterpret_cast<const uint64_t*>(a.data());
        const uint64_t* b64 = reinterpret_cast<const uint64_t*>(b.data());
        
        // Compare 16 bytes as 2x uint64_t
        if (a64[0] != b64[0] || a64[1] != b64[1]) return false;
        
        // Compare remaining 4 bytes as uint32_t
        const uint32_t* a32 = reinterpret_cast<const uint32_t*>(a.data() + 16);
        const uint32_t* b32 = reinterpret_cast<const uint32_t*>(b.data() + 16);
        return *a32 == *b32;
    }
};

using OptimizedHash160Set = std::unordered_set<std::array<uint8_t, 20>, OptimizedHash160Hash, OptimizedHash160Equal>;
static std::unique_ptr<OptimizedHash160Set> wallet_hash160s;
static bool is_initialized = false;

// PERBAIKAN: Fixed hex to binary conversion dengan proper cast
static inline void hexToBinaryFastUnchecked(const char* hex, uint8_t* out) noexcept {
    // FIXED: Cast char ke unsigned char untuk menghindari warning
    out[0]  = (hex_lookup[static_cast<unsigned char>(hex[0])]  << 4) | hex_lookup[static_cast<unsigned char>(hex[1])];
    out[1]  = (hex_lookup[static_cast<unsigned char>(hex[2])]  << 4) | hex_lookup[static_cast<unsigned char>(hex[3])];
    out[2]  = (hex_lookup[static_cast<unsigned char>(hex[4])]  << 4) | hex_lookup[static_cast<unsigned char>(hex[5])];
    out[3]  = (hex_lookup[static_cast<unsigned char>(hex[6])]  << 4) | hex_lookup[static_cast<unsigned char>(hex[7])];
    out[4]  = (hex_lookup[static_cast<unsigned char>(hex[8])]  << 4) | hex_lookup[static_cast<unsigned char>(hex[9])];
    out[5]  = (hex_lookup[static_cast<unsigned char>(hex[10])] << 4) | hex_lookup[static_cast<unsigned char>(hex[11])];
    out[6]  = (hex_lookup[static_cast<unsigned char>(hex[12])] << 4) | hex_lookup[static_cast<unsigned char>(hex[13])];
    out[7]  = (hex_lookup[static_cast<unsigned char>(hex[14])] << 4) | hex_lookup[static_cast<unsigned char>(hex[15])];
    out[8]  = (hex_lookup[static_cast<unsigned char>(hex[16])] << 4) | hex_lookup[static_cast<unsigned char>(hex[17])];
    out[9]  = (hex_lookup[static_cast<unsigned char>(hex[18])] << 4) | hex_lookup[static_cast<unsigned char>(hex[19])];
    out[10] = (hex_lookup[static_cast<unsigned char>(hex[20])] << 4) | hex_lookup[static_cast<unsigned char>(hex[21])];
    out[11] = (hex_lookup[static_cast<unsigned char>(hex[22])] << 4) | hex_lookup[static_cast<unsigned char>(hex[23])];
    out[12] = (hex_lookup[static_cast<unsigned char>(hex[24])] << 4) | hex_lookup[static_cast<unsigned char>(hex[25])];
    out[13] = (hex_lookup[static_cast<unsigned char>(hex[26])] << 4) | hex_lookup[static_cast<unsigned char>(hex[27])];
    out[14] = (hex_lookup[static_cast<unsigned char>(hex[28])] << 4) | hex_lookup[static_cast<unsigned char>(hex[29])];
    out[15] = (hex_lookup[static_cast<unsigned char>(hex[30])] << 4) | hex_lookup[static_cast<unsigned char>(hex[31])];
    out[16] = (hex_lookup[static_cast<unsigned char>(hex[32])] << 4) | hex_lookup[static_cast<unsigned char>(hex[33])];
    out[17] = (hex_lookup[static_cast<unsigned char>(hex[34])] << 4) | hex_lookup[static_cast<unsigned char>(hex[35])];
    out[18] = (hex_lookup[static_cast<unsigned char>(hex[36])] << 4) | hex_lookup[static_cast<unsigned char>(hex[37])];
    out[19] = (hex_lookup[static_cast<unsigned char>(hex[38])] << 4) | hex_lookup[static_cast<unsigned char>(hex[39])];
}

// Safe version with validation untuk init
static inline bool hexToBinaryFast(const char* hex, uint8_t* out) noexcept {
    if (!lookup_initialized) init_hex_lookup();
    
    // Quick validation for 40 hex chars
    for (int i = 0; i < 40; ++i) {
        char c = hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    
    hexToBinaryFastUnchecked(hex, out);
    return true;
}

extern "C" {

int bloom_init(const char* filename, unsigned long capacity, double error_rate) {
    if (is_initialized) {
        std::cout << "Bloom filter sudah diinisialisasi\n";
        return BLOOM_SUCCESS;
    }
    
    if (!lookup_initialized) init_hex_lookup();
    
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Warning: Tidak dapat membuka file " << filename << std::endl;
        wallet_hash160s = std::make_unique<OptimizedHash160Set>();
        is_initialized = true;
        return BLOOM_ERROR;
    }
    
    // Check file size
    file.seekg(0, std::ios::end);
    auto file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::cout << "File size: " << (file_size / 1024 / 1024) << " MB\n";
    std::cout << "Loading all entries untuk optimized checking...\n";
    
    // OPTIMASI: Reserve with better estimate + optimal load factor
    wallet_hash160s = std::make_unique<OptimizedHash160Set>();
    
    // Estimate jumlah lines berdasarkan file size (asumsi ~50 bytes per line)
    unsigned long estimated_lines = file_size / 50;
    unsigned long reserve_size = std::max(capacity, estimated_lines);
    
    wallet_hash160s->reserve(reserve_size);
    wallet_hash160s->max_load_factor(0.7f); // OPTIMASI: Lower load factor = faster lookup
    
    std::string line;
    line.reserve(64);
    
    unsigned long count = 0;
    unsigned long line_count = 0;
    std::cout << "Memuat hash160 dari " << filename << "...\n";
    
    // Process tanpa batasan, load semua data
    while (std::getline(file, line)) {
        line_count++;
        
        if (line.empty() || line.length() < 40) continue;
        
        const char* start = line.c_str();
        while (*start && (*start == ' ' || *start == '\t')) ++start;
        
        if (strlen(start) >= 40) {
            std::array<uint8_t, 20> hash160_bin;
            if (hexToBinaryFast(start, hash160_bin.data())) {
                wallet_hash160s->insert(std::move(hash160_bin));
                ++count;
                
                if (count % 500000 == 0) {
                    std::cout << "\rLoaded " << count << " hash160s..." << std::flush;
                }
            }
        }
    }
    
    // OPTIMASI: Rehash untuk optimal bucket distribution
    wallet_hash160s->rehash(wallet_hash160s->size());
    
    file.close();
    is_initialized = true;
    
    std::cout << "\nBerhasil memuat " << wallet_hash160s->size() 
              << " hash160s dari " << line_count << " lines\n";
    std::cout << "Load factor: " << wallet_hash160s->load_factor() << "\n";
    std::cout << "Bucket count: " << wallet_hash160s->bucket_count() << "\n";
    std::cout << "Optimized untuk maximum checking speed!\n";
    
    return wallet_hash160s->size() > 0 ? BLOOM_SUCCESS : BLOOM_ERROR;
}

// OPTIMASI: Fastest possible binary check
// int bloom_check_binary(const uint8_t* hash160_bytes) {
//     if (!is_initialized || !hash160_bytes || !wallet_hash160s) {
//         return BLOOM_NOT_FOUND;
//     }
    
//     // OPTIMASI: Direct construction in find call - no temporary variable
//     return wallet_hash160s->find(*reinterpret_cast<const std::array<uint8_t, 20>*>(hash160_bytes)) != wallet_hash160s->end() ? 
//            BLOOM_FOUND : BLOOM_NOT_FOUND;
// }
int bloom_check_binary(const uint8_t* hash160_bytes) {
    if (!is_initialized || !hash160_bytes || !wallet_hash160s) {
        return BLOOM_NOT_FOUND;
    }

    std::array<uint8_t, 20> key;
    std::memcpy(key.data(), hash160_bytes, 20);

    // ⬇️ Tambahkan kode ini di sini
    // std::string hex;
    // for (int i = 0; i < 20; ++i) {
    //     char buf[3];
    //     sprintf(buf, "%02x", key[i]);
    //     hex += buf;
    // }
    // std::cout << "[DEBUG] bloom_check_binary checking: " << hex << "\n";

    return wallet_hash160s->find(key) != wallet_hash160s->end() ?
           BLOOM_FOUND : BLOOM_NOT_FOUND;
}


// OPTIMASI: Fastest possible string check
int bloom_check(const char* item) {
    if (!is_initialized || !item || !wallet_hash160s) {
        return BLOOM_NOT_FOUND;
    }
    
    // OPTIMASI: Quick length check first
    if (strlen(item) != 40) {
        return BLOOM_NOT_FOUND;
    }
    
    // OPTIMASI: Stack allocated array, unchecked conversion (assume valid hex)
    alignas(8) uint8_t hash160_bin[20];
    hexToBinaryFastUnchecked(item, hash160_bin);
    
    // Direct cast and find
    return wallet_hash160s->find(*reinterpret_cast<const std::array<uint8_t, 20>*>(hash160_bin)) != wallet_hash160s->end() ? 
           BLOOM_FOUND : BLOOM_NOT_FOUND;
}

unsigned long bloom_get_size(void) {
    return is_initialized && wallet_hash160s ? wallet_hash160s->size() : 0;
}

double bloom_get_load_factor(void) {
    return is_initialized && wallet_hash160s ? wallet_hash160s->load_factor() : 0.0;
}

void bloom_cleanup(void) {
    wallet_hash160s.reset();
    is_initialized = false;
}

} // extern "C"