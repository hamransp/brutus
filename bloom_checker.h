#ifndef BLOOM_CHECKER_H
#define BLOOM_CHECKER_H

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// Return codes
#define BLOOM_SUCCESS 1
#define BLOOM_ERROR 0
#define BLOOM_NOT_FOUND 0
#define BLOOM_FOUND 1

// Fungsi interface C - pastikan semua ada extern "C"
int bloom_init(const char* filename, unsigned long capacity, double error_rate);
int bloom_check(const char* item);
int bloom_check_binary(const uint8_t* hash160_bytes);  // Pastikan ini ada
void bloom_cleanup(void);

// Fungsi tambahan
unsigned long bloom_get_size(void);
double bloom_get_load_factor(void);

#ifdef __cplusplus
}
#endif

#endif // BLOOM_CHECKER_H