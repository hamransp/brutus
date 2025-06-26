#include <immintrin.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <chrono>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <fstream>
#include <omp.h>
#include <array>
#include <utility>
#include <cstdint>
#include <climits>

#include "p2pkh_decoder.h"
#include "sha256_avx2.h"
#include "ripemd160_avx2.h"
#include "SECP256K1.h"
#include "Point.h"
#include "Int.h"
#include "IntGroup.h"

#include <random>
#include <mutex>

#include <cstdlib>
#include <map>

#include "bloom_checker.h"
#include <openssl/sha.h>


static constexpr int    POINTS_BATCH_SIZE       = 256;
static constexpr int    HASH_BATCH_SIZE         = 8;
static constexpr double STATUS_INTERVAL_SEC     = 5.0;
static constexpr double SAVE_PROGRESS_INTERVAL  = 300.0;

static int                          g_progressSaveCount = 0;
static unsigned long long           g_walletFound      = 0ULL;
static unsigned long long           g_jumpsCount       = 0ULL;
static uint64_t                     g_jumpSize         = 0ULL;
static std::vector<std::string>     g_threadPrivateKeys;

struct NotificationConfig {
    std::string endpoint_url;
    std::string phone_number;
    bool notification_enabled;
};

static NotificationConfig g_notifConfig;

// Fungsi untuk membaca file konfigurasi
bool loadNotificationConfig(const std::string& configFile, NotificationConfig& config) {
    std::ifstream ifs(configFile);
    if (!ifs) {
        std::cerr << "Warning: File konfigurasi '" << configFile << "' tidak ditemukan.\n";
        std::cerr << "Notifikasi tidak akan diaktifkan.\n";
        config.notification_enabled = false;
        return false;
    }

    config.notification_enabled = false;
    std::string line;
    
    while (std::getline(ifs, line)) {
        // Lewati baris komentar atau kosong
        if (line.empty() || line[0] == '#') continue;
        
        size_t delimPos = line.find('=');
        if (delimPos == std::string::npos) continue;
        
        std::string key = line.substr(0, delimPos);
        std::string value = line.substr(delimPos + 1);
        
        // Hapus whitespace dari key dan value
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);
        
        if (key == "endpoint_url") {
            config.endpoint_url = value;
            config.notification_enabled = true;
        } else if (key == "phone_number") {
            config.phone_number = value;
        }
    }
    
    // Validasi konfigurasi minimum
    if (config.endpoint_url.empty()) {
        std::cerr << "Warning: endpoint_url tidak ditemukan di file konfigurasi.\n";
        std::cerr << "Notifikasi tidak akan diaktifkan.\n";
        config.notification_enabled = false;
        return false;
    }
    
    std::cout << "Konfigurasi notifikasi berhasil dimuat.\n";
    std::cout << "Endpoint URL: " << config.endpoint_url << "\n";
    if (!config.phone_number.empty()) {
        std::cout << "Phone Number: " << config.phone_number << "\n";
    }
    
    return true;
}

// Fungsi untuk mengirim notifikasi wallet yang ditemukan
void sendWalletFoundNotification(const std::string& privKey,
                                const std::string& pubKey,
                                const std::string& wif,
                                const std::string& hash160) {
    // Jika notifikasi tidak diaktifkan, segera keluar
    if (!g_notifConfig.notification_enabled) return;
    
    // Buat file wallet_found.txt
    std::ofstream walletFile("wallet_found.txt", std::ios::app);
    if (walletFile) {
        // Catat waktu saat ini
        auto now = std::chrono::system_clock::now();
        auto now_time_t = std::chrono::system_clock::to_time_t(now);
        std::string timestamp = std::ctime(&now_time_t);
        // Hapus newline dari timestamp
        if (!timestamp.empty() && timestamp[timestamp.length()-1] == '\n') {
            timestamp.erase(timestamp.length()-1);
        }
        
        walletFile << "======================================\n"
                  << "WALLET DITEMUKAN! " << timestamp << "\n"
                  << "======================================\n"
                  << "Private Key: " << privKey << "\n"
                  << "Public Key: " << pubKey << "\n"
                  << "WIF: " << wif << "\n"
                  << "Hash160: " << hash160 << "\n"
                  << "======================================\n\n";
        walletFile.close();
        
        std::cout << "\nWALLET DITEMUKAN! Menyimpan ke wallet_found.txt\n";
        
        // Persiapkan pesan dengan format yang sesuai untuk WhatsApp
        // Menggunakan emoji dan format yang jelas
        std::string formattedMessage = "🔥 WALLET DITEMUKAN! 🔥\n\n ";
        formattedMessage += "📍 Hash160: " + hash160 + "\n ";
        formattedMessage += "🔑 WIF: " + wif + "\n ";
        // formattedMessage += "🔒 Private Key: " + privKey.substr(0, 10) + "...";
        formattedMessage += "🔒 Private Key: " + privKey + "\n";
        
        // Gunakan pendekatan file sementara untuk menghindari masalah escape
        std::string tempFilename = "notify_payload.json";
        std::ofstream tempFile(tempFilename);
        if (!tempFile) {
            std::cerr << "Error: Tidak dapat membuat file temporary untuk payload\n";
            return;
        }
        
        // Tulis JSON dengan format yang benar
        tempFile << "{" << std::endl;
        tempFile << "  \"phone\": \"" << g_notifConfig.phone_number << "\"," << std::endl;
        tempFile << "  \"message\": \"" << formattedMessage << "\"" << std::endl;
        tempFile << "}" << std::endl;
        tempFile.close();
        
        std::cout << "Mengirim notifikasi ke " << g_notifConfig.phone_number << "...\n";
        
        // Buat command curl dengan file payload
        std::string curlCmd = "curl -X POST -H \"Content-Type: application/json\" "
                           "--data @" + tempFilename + " " 
                           + g_notifConfig.endpoint_url;
        
        std::cout << "Menjalankan: " << curlCmd << "\n";
        
        // Jalankan curl command
        int ret = std::system(curlCmd.c_str());
        
        if (ret != 0) {
            std::cerr << "Warning: Gagal mengirim notifikasi. Kode error: " << ret << "\n";
            std::cerr << "Periksa curl_response.txt untuk detail error\n";
        } else {
            std::cout << "Notifikasi berhasil dikirim!\n";
        }
    } else {
        std::cerr << "Error: Tidak dapat membuka file wallet_found.txt untuk menulis\n";
    }
    
    // Tampilkan pemberitahuan lengkap di console
    std::cout << "\n====== WALLET DITEMUKAN ======\n";
    std::cout << "Hash160  : " << hash160 << "\n";
    std::cout << "WIF      : " << wif << "\n";
    std::cout << "Priv Key : " << privKey << "\n";
    std::cout << "Pub Key  : " << pubKey << "\n";
    std::cout << "==============================\n\n";
}

// Struktur untuk mengelola chunk-chunk pencarian
struct ChunkTracker {
    std::vector<bool> processed;  // Chunk yang sudah diproses
    std::mutex mutex;             // Mutex untuk sinkronisasi
    int totalChunks;
    int remainingChunks;

    ChunkTracker(int chunks) : totalChunks(chunks), remainingChunks(chunks) {
        processed.resize(chunks, false);
    }

    // Mendapatkan chunk yang belum diproses secara acak
    int getNextChunk(std::mt19937_64& rng) {
        std::lock_guard<std::mutex> lock(mutex);
        
        if (remainingChunks == 0) return -1; // Semua chunk sudah diproses
        
        std::uniform_int_distribution<int> dist(0, totalChunks - 1);
        int chunkId;
        
        do {
            chunkId = dist(rng);
        } while (processed[chunkId]);
        
        processed[chunkId] = true;
        remainingChunks--;
        
        return chunkId;
    }
};

struct ResumeState {
    std::vector<std::string> threadPrivKeys;
    std::vector<bool> processedChunks;
    unsigned long long totalChecked;
    double elapsedTime;
    uint64_t jumpSize;
    unsigned long long walletFound;
    unsigned long long jumpsCount;
};

// Fungsi untuk menyimpan state
void saveResumeState(const std::string& filename, const ResumeState& state) {
    std::ofstream ofs(filename, std::ios::binary);
    if (!ofs) {
        std::cerr << "Gagal membuka " << filename << " untuk menulis state\n";
        return;
    }
    
    // Simpan ukuran data vektor
    size_t privKeysSize = state.threadPrivKeys.size();
    size_t chunksSize = state.processedChunks.size();
    
    ofs.write(reinterpret_cast<const char*>(&privKeysSize), sizeof(privKeysSize));
    ofs.write(reinterpret_cast<const char*>(&chunksSize), sizeof(chunksSize));
    
    // Simpan private keys
    for (const auto& key : state.threadPrivKeys) {
        size_t keySize = key.size();
        ofs.write(reinterpret_cast<const char*>(&keySize), sizeof(keySize));
        ofs.write(key.c_str(), keySize);
    }
    
    // Simpan status chunk
    for (bool b : state.processedChunks) {
        ofs.write(reinterpret_cast<const char*>(&b), sizeof(bool));
    }
    
    // Simpan statistik global
    ofs.write(reinterpret_cast<const char*>(&state.totalChecked), sizeof(state.totalChecked));
    ofs.write(reinterpret_cast<const char*>(&state.elapsedTime), sizeof(state.elapsedTime));
    ofs.write(reinterpret_cast<const char*>(&state.jumpSize), sizeof(state.jumpSize));
    ofs.write(reinterpret_cast<const char*>(&state.walletFound), sizeof(state.walletFound));
    ofs.write(reinterpret_cast<const char*>(&state.jumpsCount), sizeof(state.jumpsCount));
}

// Fungsi untuk memuat state
bool loadResumeState(const std::string& filename, ResumeState& state) {
    std::ifstream ifs(filename, std::ios::binary);
    if (!ifs) {
        std::cerr << "State resume tidak ditemukan di " << filename << "\n";
        return false;
    }
    
    // Baca ukuran data
    size_t privKeysSize, chunksSize;
    ifs.read(reinterpret_cast<char*>(&privKeysSize), sizeof(privKeysSize));
    ifs.read(reinterpret_cast<char*>(&chunksSize), sizeof(chunksSize));
    
    // Baca private keys
    state.threadPrivKeys.resize(privKeysSize);
    for (size_t i = 0; i < privKeysSize; i++) {
        size_t keySize;
        ifs.read(reinterpret_cast<char*>(&keySize), sizeof(keySize));
        
        std::string key(keySize, '\0');
        ifs.read(&key[0], keySize);
        state.threadPrivKeys[i] = key;
    }
    
    // Baca status chunk
    state.processedChunks.resize(chunksSize);
    bool tempBool;
    for (size_t i = 0; i < chunksSize; i++) {
        ifs.read(reinterpret_cast<char*>(&tempBool), sizeof(bool));
        state.processedChunks[i] = tempBool;
    }
    
    // Baca statistik global
    ifs.read(reinterpret_cast<char*>(&state.totalChecked), sizeof(state.totalChecked));
    ifs.read(reinterpret_cast<char*>(&state.elapsedTime), sizeof(state.elapsedTime));
    ifs.read(reinterpret_cast<char*>(&state.jumpSize), sizeof(state.jumpSize));
    ifs.read(reinterpret_cast<char*>(&state.walletFound), sizeof(state.walletFound));
    ifs.read(reinterpret_cast<char*>(&state.jumpsCount), sizeof(state.jumpsCount));
    
    return true;
}

static inline std::string bytesToHex(const uint8_t* data, size_t len)
{
    static constexpr char lut[] = "0123456789abcdef";
    std::string out; out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = data[i];
        out.push_back(lut[b >> 4]);
        out.push_back(lut[b & 0x0F]);
    }
    return out;
}

void saveProgressToFile(const std::string &progressStr)
{
    std::ofstream ofs("progress.txt", std::ios::app);
    if (ofs) ofs << progressStr << "\n";
    else     std::cerr << "Cannot open progress.txt for writing\n";
}

std::vector<uint64_t> bigNumMultiply(const std::vector<uint64_t>& a, uint64_t b)
{
    std::vector<uint64_t> result;
    result.reserve(a.size() + 1);
    
    uint64_t carry = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        __uint128_t product = (__uint128_t)a[i] * b + carry;
        result.push_back(uint64_t(product));
        carry = uint64_t(product >> 64);
    }
    
    if (carry) result.push_back(carry);
    return result;
}

std::vector<uint64_t> hexToBigNum(const std::string& hex)
{
    std::vector<uint64_t> bigNum;
    const size_t len = hex.size();
    bigNum.reserve((len + 15) / 16);
    for (size_t i = 0; i < len; i += 16) {
        size_t start   = (len >= 16 + i) ? len - 16 - i : 0;
        size_t partLen = (len >= 16 + i) ? 16           : (len - i);
        uint64_t value = std::stoull(hex.substr(start, partLen), nullptr, 16);
        bigNum.push_back(value);
    }
    return bigNum;
}

std::string bigNumToHex(const std::vector<uint64_t>& num)
{
    std::ostringstream oss;
    oss << std::hex;
    for (auto it = num.rbegin(); it != num.rend(); ++it) {
        if (it != num.rbegin()) oss << std::setw(16) << std::setfill('0');
        oss << *it;
    }
    return oss.str();
}

std::vector<uint64_t> singleElementVector(uint64_t v) { return {v}; }

std::vector<uint64_t> bigNumAdd(const std::vector<uint64_t>& a,
                                const std::vector<uint64_t>& b)
{
    std::vector<uint64_t> s;
    s.reserve(std::max(a.size(), b.size()) + 1);
    uint64_t carry = 0;
    for (size_t i = 0, sz = std::max(a.size(), b.size()); i < sz; ++i) {
        uint64_t x = (i < a.size()) ? a[i] : 0ULL;
        uint64_t y = (i < b.size()) ? b[i] : 0ULL;
        __uint128_t t = (__uint128_t)x + y + carry;
        carry = uint64_t(t >> 64);
        s.push_back(uint64_t(t));
    }
    if (carry) s.push_back(carry);
    return s;
}

std::vector<uint64_t> bigNumSubtract(const std::vector<uint64_t>& a,
                                     const std::vector<uint64_t>& b)
{
    std::vector<uint64_t> d = a;
    uint64_t borrow = 0;
    for (size_t i = 0; i < b.size(); ++i) {
        uint64_t sub = b[i];
        if (d[i] < sub + borrow) {
            d[i] = d[i] + (~0ULL) - sub - borrow + 1ULL;
            borrow = 1ULL;
        } else {
            d[i] -= sub + borrow;
            borrow = 0ULL;
        }
    }
    for (size_t i = b.size(); borrow && i < d.size(); ++i) {
        if (d[i] == 0ULL) d[i] = ~0ULL;
        else { d[i] -= 1ULL; borrow = 0ULL; }
    }
    while (!d.empty() && d.back() == 0ULL) d.pop_back();
    return d;
}

std::pair<std::vector<uint64_t>, uint64_t> bigNumDivide(
    const std::vector<uint64_t>& a, uint64_t divisor)
{
    std::vector<uint64_t> q(a.size(), 0ULL);
    uint64_t r = 0ULL;
    for (int i = int(a.size()) - 1; i >= 0; --i) {
        __uint128_t t = ((__uint128_t)r << 64) | a[i];
        q[i] = uint64_t(t / divisor);
        r    = uint64_t(t % divisor);
    }
    while (!q.empty() && q.back() == 0ULL) q.pop_back();
    return {q, r};
}

long double hexStrToLongDouble(const std::string& h)
{
    long double res = 0.0L;
    for (char c: h) {
        res *= 16.0L;
        if      (c >= '0' && c <= '9') res += (c - '0');
        else if (c >= 'a' && c <= 'f') res += (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') res += (c - 'A' + 10);
    }
    return res;
}

static inline std::string padHexTo64(const std::string& h)
{
    return (h.size() >= 64) ? h : std::string(64 - h.size(), '0') + h;
}

static inline Int hexToInt(const std::string& h)
{
    Int n; char buf[65] = {0};
    std::strncpy(buf, h.c_str(), 64);
    n.SetBase16(buf);
    return n;
}

static inline std::string intToHex(const Int& v)
{
    Int t; t.Set((Int*)&v); return t.GetBase16();
}

static inline bool intGreater(const Int& a,const Int& b)
{
    std::string ha=((Int&)a).GetBase16(), hb=((Int&)b).GetBase16();
    return ha.size()!=hb.size() ? ha.size()>hb.size() : ha>hb;
}

static inline bool isEven(const Int& n) { return n.IsEven(); } 

static inline std::string intXToHex64(const Int& x)
{
    Int t; t.Set((Int*)&x);
    std::string h=t.GetBase16();
    if (h.size()<64) h.insert(0,64-h.size(),'0');
    return h;
}

static inline std::string pointToCompressedHex(const Point& p)
{
    return (isEven(p.y) ? "02" : "03") + intXToHex64(p.x);
}

static inline void pointToCompressedBin(const Point& p,uint8_t out[33])
{
    out[0] = isEven(p.y) ? 0x02 : 0x03;
    Int t; t.Set((Int*)&p.x);
    for (int i = 0; i < 32; ++i)
        out[1+i] = uint8_t(t.GetByte(31-i));
}

static inline void pointToUncompressedBin(const Point& p, uint8_t out[65])
{
    out[0] = 0x04;  // Prefix untuk uncompressed
    Int tx, ty;
    tx.Set((Int*)&p.x);
    ty.Set((Int*)&p.y);
    
    for (int i = 0; i < 32; ++i) {
        out[1+i] = uint8_t(tx.GetByte(31-i));      // X coordinate
        out[33+i] = uint8_t(ty.GetByte(31-i));     // Y coordinate  
    }
}

inline void prepareShaBlock(const uint8_t* src,size_t len,uint8_t* out)
{
    std::fill_n(out,64,0);
    std::memcpy(out,src,len);
    out[len]=0x80;
    uint32_t bitLen = uint32_t(len*8);
    out[60]=uint8_t(bitLen>>24);
    out[61]=uint8_t(bitLen>>16);
    out[62]=uint8_t(bitLen>> 8);
    out[63]=uint8_t(bitLen    );
}

inline void prepareShaBlockUncompressed(const uint8_t* src, uint8_t* out)
{
    std::fill_n(out, 64, 0);
    std::memcpy(out, src, 65);
    out[65] = 0x80;
    uint32_t bitLen = uint32_t(65 * 8);  // 65 bytes = 520 bits
    out[60] = uint8_t(bitLen >> 24);
    out[61] = uint8_t(bitLen >> 16);
    out[62] = uint8_t(bitLen >> 8);
    out[63] = uint8_t(bitLen);
}

inline void prepareRipemdBlock(const uint8_t* src,uint8_t* out)
{
    std::fill_n(out,64,0);
    std::memcpy(out,src,32);
    out[32]=0x80;
    uint32_t bitLen=256;
    out[60]=uint8_t(bitLen>>24);
    out[61]=uint8_t(bitLen>>16);
    out[62]=uint8_t(bitLen>> 8);
    out[63]=uint8_t(bitLen    );
}

static void computeHash160BatchBinSingle(int nKeys,
                                         uint8_t pub[][33],
                                         uint8_t outHash[][20])
{
    std::array<std::array<uint8_t,64>,HASH_BATCH_SIZE> shaIn;
    std::array<std::array<uint8_t,32>,HASH_BATCH_SIZE> shaOut;
    std::array<std::array<uint8_t,64>,HASH_BATCH_SIZE> ripIn;
    std::array<std::array<uint8_t,20>,HASH_BATCH_SIZE> ripOut;

    size_t nBatches=(nKeys+HASH_BATCH_SIZE-1)/HASH_BATCH_SIZE;

    for (size_t b = 0; b < nBatches; ++b) {
        size_t cnt = std::min<size_t>(HASH_BATCH_SIZE, nKeys - b*HASH_BATCH_SIZE);

        for (size_t i = 0; i < cnt; ++i)
            prepareShaBlock(pub[b*HASH_BATCH_SIZE+i],33,shaIn[i].data());
        for (size_t i = cnt; i < HASH_BATCH_SIZE; ++i)
            std::memcpy(shaIn[i].data(),shaIn[0].data(),64);

        const uint8_t* in[HASH_BATCH_SIZE];
        uint8_t*       out[HASH_BATCH_SIZE];
        for (int i = 0; i < HASH_BATCH_SIZE; ++i) {
            in[i]=shaIn[i].data();
            out[i]=shaOut[i].data();
        }
        sha256avx2_8B(in[0],in[1],in[2],in[3],in[4],in[5],in[6],in[7],
                      out[0],out[1],out[2],out[3],out[4],out[5],out[6],out[7]);

        for (size_t i = 0; i < cnt; ++i)
            prepareRipemdBlock(shaOut[i].data(),ripIn[i].data());
        for (size_t i = cnt; i < HASH_BATCH_SIZE; ++i)
            std::memcpy(ripIn[i].data(),ripIn[0].data(),64);

        for (int i = 0; i < HASH_BATCH_SIZE; ++i) {
            in[i]=ripIn[i].data();
            out[i]=ripOut[i].data();
        }
        ripemd160avx2::ripemd160avx2_32(
            (unsigned char*)in[0],(unsigned char*)in[1],(unsigned char*)in[2],
            (unsigned char*)in[3],(unsigned char*)in[4],(unsigned char*)in[5],
            (unsigned char*)in[6],(unsigned char*)in[7],
            out[0],out[1],out[2],out[3],out[4],out[5],out[6],out[7]);

        for (size_t i = 0; i < cnt; ++i)
            std::memcpy(outHash[b*HASH_BATCH_SIZE+i],ripOut[i].data(),20);
    }
}
static void computeHash160BatchBinUncompressed(int nKeys,
                                               uint8_t pub[][65], 
                                               uint8_t outHash[][20])
{
    std::array<std::array<uint8_t,32>,HASH_BATCH_SIZE> shaOut;
    std::array<std::array<uint8_t,64>,HASH_BATCH_SIZE> ripIn;
    std::array<std::array<uint8_t,20>,HASH_BATCH_SIZE> ripOut;

    size_t nBatches = (nKeys + HASH_BATCH_SIZE - 1) / HASH_BATCH_SIZE;

    for (size_t b = 0; b < nBatches; ++b) {
        size_t cnt = std::min<size_t>(HASH_BATCH_SIZE, nKeys - b * HASH_BATCH_SIZE);

        // Menggunakan AVX2 untuk hashing SHA256 untuk uncompressed keys
        for (size_t i = 0; i < cnt; ++i) {
            prepareShaBlockUncompressed(pub[b * HASH_BATCH_SIZE + i], shaOut[i].data());
        }

        // Lakukan pemrosesan untuk batch yang ada
        const uint8_t* in[HASH_BATCH_SIZE];
        uint8_t* out[HASH_BATCH_SIZE];
        for (int i = 0; i < HASH_BATCH_SIZE; ++i) {
            in[i] = shaOut[i].data();
            out[i] = shaOut[i].data(); // Hasil SHA256 langsung di-shaOut
        }

        // Gantikan OpenSSL SHA256 dengan SHA256 AVX2
        sha256avx2_8B(in[0], in[1], in[2], in[3], in[4], in[5], in[6], in[7],
                      out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]);

        // Proses RIPEMD160 seperti biasa
        for (size_t i = 0; i < cnt; ++i)
            prepareRipemdBlock(shaOut[i].data(), ripIn[i].data());
        for (size_t i = cnt; i < HASH_BATCH_SIZE; ++i)
            std::memcpy(ripIn[i].data(), ripIn[0].data(), 64);

        for (int i = 0; i < HASH_BATCH_SIZE; ++i) {
            in[i] = ripIn[i].data();
            out[i] = ripOut[i].data();
        }

        // Proses RIPEMD160 AVX2
        ripemd160avx2::ripemd160avx2_32(
            (unsigned char*)in[0], (unsigned char*)in[1], (unsigned char*)in[2],
            (unsigned char*)in[3], (unsigned char*)in[4], (unsigned char*)in[5],
            (unsigned char*)in[6], (unsigned char*)in[7],
            out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]);

        // Salin hasil RIPEMD160 ke outHash
        for (size_t i = 0; i < cnt; ++i)
            std::memcpy(outHash[b * HASH_BATCH_SIZE + i], ripOut[i].data(), 20);
    }
}


// ✅ UPDATE: Unified hash computation function
static void computeHash160BatchBinUnified(int nKeys,
                                          uint8_t pubCompressed[][33],
                                          uint8_t pubUncompressed[][65], 
                                          uint8_t outHashCompressed[][20],
                                          uint8_t outHashUncompressed[][20])
{
    std::array<std::array<uint8_t,32>,HASH_BATCH_SIZE> shaOutComp, shaOutUncomp;
    std::array<std::array<uint8_t,64>,HASH_BATCH_SIZE> ripInComp, ripInUncomp;
    std::array<std::array<uint8_t,20>,HASH_BATCH_SIZE> ripOutComp, ripOutUncomp;

    size_t nBatches = (nKeys + HASH_BATCH_SIZE - 1) / HASH_BATCH_SIZE;

    for (size_t b = 0; b < nBatches; ++b) {
        size_t cnt = std::min<size_t>(HASH_BATCH_SIZE, nKeys - b * HASH_BATCH_SIZE);

        // Setup pointers untuk compressed
        const uint8_t* inComp[HASH_BATCH_SIZE];
        uint8_t* outComp[HASH_BATCH_SIZE];
        
        // Setup pointers untuk uncompressed  
        const uint8_t* inUncomp[HASH_BATCH_SIZE];
        uint8_t* outUncomp[HASH_BATCH_SIZE];
        
        for (size_t i = 0; i < cnt; ++i) {
            inComp[i] = pubCompressed[b * HASH_BATCH_SIZE + i];
            outComp[i] = shaOutComp[i].data();
            
            inUncomp[i] = pubUncompressed[b * HASH_BATCH_SIZE + i];
            outUncomp[i] = shaOutUncomp[i].data();
        }
        
        // Fill remainder dengan duplikat first element
        for (size_t i = cnt; i < HASH_BATCH_SIZE; ++i) {
            inComp[i] = pubCompressed[b * HASH_BATCH_SIZE];
            outComp[i] = shaOutComp[i].data();
            
            inUncomp[i] = pubUncompressed[b * HASH_BATCH_SIZE];
            outUncomp[i] = shaOutUncomp[i].data();
        }

        // ✅ SHA256 untuk compressed keys (33 bytes)
        sha256avx2_8B_variable(
            inComp[0], inComp[1], inComp[2], inComp[3], 
            inComp[4], inComp[5], inComp[6], inComp[7],
            33, // Compressed length
            outComp[0], outComp[1], outComp[2], outComp[3], 
            outComp[4], outComp[5], outComp[6], outComp[7]
        );

        // ✅ SHA256 untuk uncompressed keys (65 bytes)
        sha256avx2_8B_variable(
            inUncomp[0], inUncomp[1], inUncomp[2], inUncomp[3], 
            inUncomp[4], inUncomp[5], inUncomp[6], inUncomp[7],
            65, // Uncompressed length
            outUncomp[0], outUncomp[1], outUncomp[2], outUncomp[3], 
            outUncomp[4], outUncomp[5], outUncomp[6], outUncomp[7]
        );

        // ✅ RIPEMD160 untuk compressed
        for (size_t i = 0; i < cnt; ++i)
            prepareRipemdBlock(shaOutComp[i].data(), ripInComp[i].data());
        for (size_t i = cnt; i < HASH_BATCH_SIZE; ++i)
            std::memcpy(ripInComp[i].data(), ripInComp[0].data(), 64);

        const uint8_t* ripInCompPtr[HASH_BATCH_SIZE];
        uint8_t* ripOutCompPtr[HASH_BATCH_SIZE];
        for (int i = 0; i < HASH_BATCH_SIZE; ++i) {
            ripInCompPtr[i] = ripInComp[i].data();
            ripOutCompPtr[i] = ripOutComp[i].data();
        }

        ripemd160avx2::ripemd160avx2_32(
            (unsigned char*)ripInCompPtr[0], (unsigned char*)ripInCompPtr[1], 
            (unsigned char*)ripInCompPtr[2], (unsigned char*)ripInCompPtr[3],
            (unsigned char*)ripInCompPtr[4], (unsigned char*)ripInCompPtr[5], 
            (unsigned char*)ripInCompPtr[6], (unsigned char*)ripInCompPtr[7],
            ripOutCompPtr[0], ripOutCompPtr[1], ripOutCompPtr[2], ripOutCompPtr[3], 
            ripOutCompPtr[4], ripOutCompPtr[5], ripOutCompPtr[6], ripOutCompPtr[7]
        );

        // ✅ RIPEMD160 untuk uncompressed
        for (size_t i = 0; i < cnt; ++i)
            prepareRipemdBlock(shaOutUncomp[i].data(), ripInUncomp[i].data());
        for (size_t i = cnt; i < HASH_BATCH_SIZE; ++i)
            std::memcpy(ripInUncomp[i].data(), ripInUncomp[0].data(), 64);

        const uint8_t* ripInUncompPtr[HASH_BATCH_SIZE];
        uint8_t* ripOutUncompPtr[HASH_BATCH_SIZE];
        for (int i = 0; i < HASH_BATCH_SIZE; ++i) {
            ripInUncompPtr[i] = ripInUncomp[i].data();
            ripOutUncompPtr[i] = ripOutUncomp[i].data();
        }

        ripemd160avx2::ripemd160avx2_32(
            (unsigned char*)ripInUncompPtr[0], (unsigned char*)ripInUncompPtr[1], 
            (unsigned char*)ripInUncompPtr[2], (unsigned char*)ripInUncompPtr[3],
            (unsigned char*)ripInUncompPtr[4], (unsigned char*)ripInUncompPtr[5], 
            (unsigned char*)ripInUncompPtr[6], (unsigned char*)ripInUncompPtr[7],
            ripOutUncompPtr[0], ripOutUncompPtr[1], ripOutUncompPtr[2], ripOutUncompPtr[3], 
            ripOutUncompPtr[4], ripOutUncompPtr[5], ripOutUncompPtr[6], ripOutUncompPtr[7]
        );

        // Copy results
        for (size_t i = 0; i < cnt; ++i) {
            std::memcpy(outHashCompressed[b * HASH_BATCH_SIZE + i], ripOutComp[i].data(), 20);
            std::memcpy(outHashUncompressed[b * HASH_BATCH_SIZE + i], ripOutUncomp[i].data(), 20);
        }
    }
}


static void printUsage(const char* prog)
{
    std::cerr<<"Usage: "<<prog
             <<" -r <START:END>"
             <<" [-j <JUMP>] [-f <START%:END%>] [-random] [-chunks <NUM>] [-resume]\n";
}

static std::string formatElapsedTime(double sec)
{
    int h=int(sec)/3600, m=(int(sec)%3600)/60, s=int(sec)%60;
    std::ostringstream oss;
    oss<<std::setw(2)<<std::setfill('0')<<h<<":"
       <<std::setw(2)<<m<<":"
       <<std::setw(2)<<s;
    return oss.str();
}

static void printStats(int nCPU,
                       const std::string& range,
                       double mks,
                       unsigned long long checked,
                       double elapsed,
                       int saves,
                       long double prog,
                       unsigned long long walletCnt,
                       bool showJump,
                       unsigned long long jumpCnt)
{
    // std::cout<<"\n";
    const int lines = 10 + (showJump?1:0); 
    static bool first=true;
    if(!first) std::cout<<"\033["<<lines<<"A";
    else       first=false;
    std::cout<<"============= Bismillahirahmanirahim =============\n"
            //  <<"Start Time    : "<<std::fixed<<std::setprecision(2)<<std::chrono::duration<double>(std::chrono::high_resolution_clock::now().time_since_epoch()).count()<<"\n"
             <<"CPU Threads   : "<<nCPU<<"\n"
             <<"Mkeys/s       : "<<std::fixed<<std::setprecision(2)<<mks<<"\n"
             <<"Total Checked : "<<checked<<"\n"
             <<"Elapsed Time  : "<<formatElapsedTime(elapsed)<<"\n"
             <<"Range         : "<<range<<"\n"
             <<"Progress      : "<<std::fixed<<std::setprecision(8)<<prog<<" %\n"
             <<"Progress Save : "<<saves<<"\n"
             <<"Wallets Found : "<<walletCnt<<"\n";
    if (showJump) std::cout<<"Jumps         : "<<jumpCnt<<"\n";
    std::cout<<"===================================================\n";
    std::cout.flush();
}

struct ThreadRange { std::string startHex,endHex; };
static std::vector<ThreadRange> g_threadRanges;
// Variabel global tambahan
static ChunkTracker* g_chunkTracker = nullptr;
static std::vector<std::mt19937_64> g_threadRngs;
static std::mutex g_saveStateMutex;


int main(int argc, char* argv[])
{
    bool rOK=false, jOK=false, fOK=false;
    bool randomMode = false, resumeMode = false;
    int  numChunks = 1000; // Default jumlah chunk untuk mode random
    uint64_t jumpSize=0ULL;
    std::string rangeStr;
    std::string focusRangeStr; // untuk menyimpan parameter rentang fokus
    double focusStart=0.0, focusEnd=100.0; // nilai default 0-100%

    loadNotificationConfig("config.txt", g_notifConfig);
    bloom_init("wallets_hash160.txt", 60000000UL, 0.001);

    for(int i=1;i<argc;++i){
        if(!std::strcmp(argv[i],"-r") && i+1<argc){
            rangeStr=argv[++i]; rOK=true;
        }
        else if(!std::strcmp(argv[i],"-j") && i+1<argc){
            jumpSize=std::stoull(argv[++i]); jOK=true;
            if(jumpSize==0){
                std::cerr<<"-j harus lebih dari 0\n"; return 1;
            }
        }
        else if(!std::strcmp(argv[i],"-f") && i+1<argc){
            focusRangeStr=argv[++i]; fOK=true;
            // Parse rentang fokus (format: "start%:end%")
            size_t colon = focusRangeStr.find(':');
            if(colon == std::string::npos){
                std::cerr<<"-f format harus START%:END%\n"; return 1;
            }
            try {
                focusStart = std::stod(focusRangeStr.substr(0, colon));
                focusEnd = std::stod(focusRangeStr.substr(colon+1));
                if(focusStart < 0 || focusStart > 100 || focusEnd < 0 || focusEnd > 100 || focusStart >= focusEnd) {
                    std::cerr<<"-f memerlukan nilai antara 0-100 dan start < end\n"; return 1;
                }
            } catch(const std::exception& e) {
                std::cerr<<"Error parsing -f parameter: "<<e.what()<<"\n"; return 1;
            }
        }
        else if(!std::strcmp(argv[i],"-random")){
            randomMode = true;
        }
        else if(!std::strcmp(argv[i],"-chunks") && i+1<argc){
            numChunks = std::stoi(argv[++i]);
            if(numChunks < 1) {
                std::cerr<<"Jumlah chunk harus minimal 1\n"; return 1;
            }
        }
        else if(!std::strcmp(argv[i],"-resume")){
            resumeMode = true;
        }
        else{
            printUsage(argv[0]); return 1;
        }
    }
    if(!rOK){ printUsage(argv[0]); return 1; }

    const bool jumpEnabled = jOK;
    g_jumpSize = jumpEnabled ? jumpSize : 0ULL;

    size_t colon=rangeStr.find(':');
    if(colon==std::string::npos){ std::cerr<<"Format range salah\n"; return 1; }
    std::string startHex=rangeStr.substr(0,colon);
    std::string endHex  =rangeStr.substr(colon+1);

    auto startBN=hexToBigNum(startHex), endBN=hexToBigNum(endHex);

    bool okRange=false;
    if(startBN.size()<endBN.size()) okRange=true;
    else if(startBN.size()==endBN.size()){
        okRange=true;
        for(int i=int(startBN.size())-1;i>=0;--i){
            if(startBN[i]<endBN[i]) break;
            if(startBN[i]>endBN[i]){ okRange=false; break; }
        }
    }
    if(!okRange){ std::cerr<<"Range start > end\n"; return 1; }

    auto rangeSize=bigNumAdd(bigNumSubtract(endBN,startBN),
                             singleElementVector(1ULL));

    // Menerapkan rentang fokus jika opsi -f digunakan
    if(fOK) {
        // Hitung offset untuk start dan end berdasarkan persentase
        std::vector<uint64_t> rangePercentStart = bigNumDivide(
            bigNumSubtract(
                bigNumAdd(
                    startBN,
                    bigNumDivide(
                        bigNumMultiply(rangeSize, static_cast<uint64_t>(focusStart * 100ULL)),
                        10000ULL
                    ).first
                ),
                singleElementVector(1ULL)
            ),
            1ULL
        ).first;
        
        std::vector<uint64_t> rangePercentEnd = bigNumDivide(
            bigNumAdd(
                startBN,
                bigNumDivide(
                    bigNumMultiply(rangeSize, static_cast<uint64_t>(focusEnd * 100ULL)),
                    10000ULL
                ).first
            ),
            1ULL
        ).first;
        
        // Update rentang pencarian
        startBN = rangePercentStart;
        endBN = rangePercentEnd;
        
        // Recalculate rangeSize untuk rentang baru
        rangeSize = bigNumAdd(bigNumSubtract(endBN, startBN), singleElementVector(1ULL));
        
        // Update startHex dan endHex untuk tampilan
        startHex = bigNumToHex(startBN);
        endHex = bigNumToHex(endBN);
        
        std::cout << "Rentang fokus diterapkan: " << focusStart << "% hingga " << focusEnd << "%\n";
        std::cout << "Rentang pencarian baru: " << startHex << ":" << endHex << "\n";
    }

    long double totalRangeLD=hexStrToLongDouble(bigNumToHex(rangeSize));

    int numCPUs=omp_get_num_procs();
    g_threadPrivateKeys.assign(numCPUs,"0");

    // Inisialisasi RNG untuk setiap thread
    g_threadRngs.resize(numCPUs);
    for(int i = 0; i < numCPUs; i++) {
        std::random_device rd;
        g_threadRngs[i].seed(rd() + i); // Seed berbeda untuk setiap thread
    }

    // Variabel untuk resume
    ResumeState resumeState;
    unsigned long long globalChecked=0ULL;
    double globalElapsed=0.0, mkeys=0.0;
    
    auto tStart = std::chrono::high_resolution_clock::now();
    
    // Jika dalam mode resume, coba load state
    if(resumeMode) {
        if(loadResumeState("resume.state", resumeState)) {
            globalChecked = resumeState.totalChecked;
            globalElapsed = resumeState.elapsedTime;
            g_jumpSize = resumeState.jumpSize;
            g_walletFound = resumeState.walletFound;
            g_jumpsCount = resumeState.jumpsCount;
            
            // Restore private keys jika ada
            if(!resumeState.threadPrivKeys.empty()) {
                if(resumeState.threadPrivKeys.size() <= g_threadPrivateKeys.size()) {
                    for(size_t i = 0; i < resumeState.threadPrivKeys.size(); i++) {
                        g_threadPrivateKeys[i] = resumeState.threadPrivKeys[i];
                    }
                } else {
                    std::cerr << "Peringatan: Jumlah thread berbeda dari resume sebelumnya\n";
                }
            }
            
            std::cout << "Melanjutkan pencarian sebelumnya. Sudah diperiksa " << globalChecked 
                     << " keys dalam " << formatElapsedTime(globalElapsed) << "\n";
                     
            // Sesuaikan waktu mulai agar statistik tetap konsisten
            auto now = std::chrono::high_resolution_clock::now();
            auto elapsed_duration = std::chrono::duration_cast<std::chrono::high_resolution_clock::duration>(
                std::chrono::duration<double>(globalElapsed));
            tStart = now - elapsed_duration;
        } else {
            std::cout << "State resume tidak ditemukan, memulai pencarian baru.\n";
        }
    }
    
    auto lastStat = std::chrono::high_resolution_clock::now();
    auto lastSave = lastStat;

    // Siapkan chunk tracker jika menggunakan mode random
    if(randomMode) {
        g_chunkTracker = new ChunkTracker(numChunks);
        
        // Jika resume mode dan ada data chunk sebelumnya, restore status chunk
        if(resumeMode && !resumeState.processedChunks.empty()) {
            for(size_t i = 0; i < resumeState.processedChunks.size() && 
                i < g_chunkTracker->processed.size(); i++) {
                g_chunkTracker->processed[i] = resumeState.processedChunks[i];
                if(resumeState.processedChunks[i]) {
                    g_chunkTracker->remainingChunks--;
                }
            }
            std::cout << "Pemrosesan chunk dilanjutkan dengan " 
                     << g_chunkTracker->remainingChunks << " chunk tersisa dari " 
                     << numChunks << "\n";
        }
    } else {
        // Mode sequential: persiapkan range per thread
        auto [chunk,remainder]=bigNumDivide(rangeSize,(uint64_t)numCPUs);
        g_threadRanges.resize(numCPUs);
        std::vector<uint64_t> cur=startBN;
        for(int t=0;t<numCPUs;++t){
            auto e=bigNumAdd(cur,chunk);
            if(t<remainder) e=bigNumAdd(e,singleElementVector(1ULL));
            e=bigNumSubtract(e,singleElementVector(1ULL));
            g_threadRanges[t].startHex=bigNumToHex(cur);
            g_threadRanges[t].endHex  =bigNumToHex(e);
            cur=bigNumAdd(e,singleElementVector(1ULL));
        }
    }

    std::string displayRange = randomMode ? 
                               startHex + ":" + endHex : 
                               g_threadRanges.front().startHex + ":" + g_threadRanges.back().endHex;

    std::string foundPriv, foundPub, foundWIF;

    Secp256K1 secp; secp.Init();
    Int i512; i512.SetInt32(510);
    Point big512G=secp.ComputePublicKey(&i512);

#pragma omp parallel num_threads(numCPUs) \
    shared(globalChecked,globalElapsed,mkeys, \
           foundPriv,foundPub,foundWIF, \
           tStart,lastStat,lastSave,g_progressSaveCount, \
           g_threadPrivateKeys,g_walletFound,g_jumpsCount, \
           g_chunkTracker,resumeState)
    {
        int tid=omp_get_thread_num();
        unsigned long long localChecked=0ULL;
        unsigned long long localJumps=0ULL;
        
        // Setup point calculation cache
        std::vector<Point> plus(POINTS_BATCH_SIZE), minus(POINTS_BATCH_SIZE);
        for(int i=0;i<POINTS_BATCH_SIZE;++i){
            Int t; t.SetInt32(i);
            Point p=secp.ComputePublicKey(&t);
            plus[i]=p; p.y.ModNeg(); minus[i]=p;
        }
        std::vector<Int>  deltaX(POINTS_BATCH_SIZE);
        IntGroup          modGrp(POINTS_BATCH_SIZE);
        
        // const int fullBatch=2*POINTS_BATCH_SIZE;
        // std::vector<Point> ptBatch(fullBatch);
        // uint8_t pubKeys[fullBatch][33];
        // uint8_t hashRes[HASH_BATCH_SIZE][20];
        // int localCnt=0, idxArr[HASH_BATCH_SIZE];
        const int fullBatch = 2 * POINTS_BATCH_SIZE;
        std::vector<Point> ptBatch(fullBatch);
        uint8_t pubKeysCompressed[fullBatch][33];
        uint8_t pubKeysUncompressed[fullBatch][65];
        uint8_t hashResCompressed[HASH_BATCH_SIZE][20];
        uint8_t hashResUncompressed[HASH_BATCH_SIZE][20];
        int localCnt = 0, idxArr[HASH_BATCH_SIZE];
        
        // Setup jump variable
        Int jumpInt;
        if(jumpEnabled){
            std::ostringstream oss; oss << std::hex << g_jumpSize;
            jumpInt = hexToInt(oss.str());        
        }
        
        if(randomMode && g_chunkTracker) {
            // Mode random: ambil chunk secara acak
            int chunkId;
            while((chunkId = g_chunkTracker->getNextChunk(g_threadRngs[tid])) != -1) {
                // Hitung range untuk chunk ini
                auto chunkSize = bigNumDivide(rangeSize, (uint64_t)numChunks).first;
                auto chunkStart = bigNumAdd(startBN, bigNumMultiply(chunkSize, (uint64_t)chunkId));
                auto chunkEnd = (chunkId == numChunks - 1) ? 
                            endBN : 
                            bigNumSubtract(bigNumAdd(chunkStart, chunkSize), singleElementVector(1ULL));
                
                // Set private key ke awal chunk
                Int priv = hexToInt(bigNumToHex(chunkStart));
                const Int privEnd = hexToInt(bigNumToHex(chunkEnd));
                Point base = secp.ComputePublicKey(&priv);
                
                while(!intGreater(priv, privEnd)) {
                    #pragma omp critical
                    g_threadPrivateKeys[tid] = padHexTo64(intToHex(priv));
                    
                    // Kode perhitungan point batch dan hash
                    for(int i=0;i<POINTS_BATCH_SIZE;++i){
                        deltaX[i].ModSub(&plus[i].x,&base.x);
                    }
                    modGrp.Set(deltaX.data()); modGrp.ModInv();
                    
                    for(int i=0;i<POINTS_BATCH_SIZE;++i){
                        Point r=base;
                        Int dY; dY.ModSub(&plus[i].y,&base.y);
                        Int k; k.ModMulK1(&dY,&deltaX[i]);
                        Int k2; k2.ModSquareK1(&k);
                        Int xNew; xNew.Set(&base.x); xNew.ModNeg(); xNew.ModAdd(&k2);
                        xNew.ModSub(&plus[i].x); r.x.Set(&xNew);
                        Int dx; dx.Set(&base.x); dx.ModSub(&r.x); dx.ModMulK1(&k);
                        r.y.ModNeg(); r.y.ModAdd(&dx);
                        ptBatch[i]=r;
                    }
                    for(int i=0;i<POINTS_BATCH_SIZE;++i){
                        Point r=base;
                        Int dY; dY.ModSub(&minus[i].y,&base.y);
                        Int k; k.ModMulK1(&dY,&deltaX[i]);
                        Int k2; k2.ModSquareK1(&k);
                        Int xNew; xNew.Set(&base.x); xNew.ModNeg(); xNew.ModAdd(&k2);
                        xNew.ModSub(&minus[i].x); r.x.Set(&xNew);
                        Int dx; dx.Set(&base.x); dx.ModSub(&r.x); dx.ModMulK1(&k);
                        r.y.ModNeg(); r.y.ModAdd(&dx);
                        ptBatch[POINTS_BATCH_SIZE+i]=r;
                    }
                    
                    unsigned int pendingJumps = 0;
                    
                    for (int i = 0; i < fullBatch; ++i) {
                        pointToCompressedBin(ptBatch[i], pubKeysCompressed[localCnt]);
                        pointToUncompressedBin(ptBatch[i], pubKeysUncompressed[localCnt]);
                        idxArr[localCnt] = i;
                        ++localCnt;
                        
                        if (localCnt == HASH_BATCH_SIZE) {
                            // Compute hash160 for both compressed and uncompressed
                            // computeHash160BatchBinSingle(localCnt, pubKeysCompressed, hashResCompressed);
                            // computeHash160BatchBinUncompressed(localCnt, pubKeysUncompressed, hashResUncompressed);
                            computeHash160BatchBinUnified(localCnt, 
                                      pubKeysCompressed, pubKeysUncompressed,
                                      hashResCompressed, hashResUncompressed);
                            
                            for (int j = 0; j < HASH_BATCH_SIZE; ++j) {
                                bool found = false;
                                std::string addressType;
                                const uint8_t* foundHash = nullptr;
                                
                                // Check compressed address
                                if (bloom_check_binary(hashResCompressed[j]) == 1) {
                                    found = true;
                                    addressType = "Compressed";
                                    foundHash = hashResCompressed[j];
                                }
                                // Check uncompressed address  
                                else if (bloom_check_binary(hashResUncompressed[j]) == 1) {
                                    found = true;
                                    addressType = "Uncompressed";
                                    foundHash = hashResUncompressed[j];
                                }
                                
                                if (found) {
                                    // WALLET DITEMUKAN!
                                    Int cPriv = priv;
                                    int idx = idxArr[j];
                                    if (idx < 256) { 
                                        Int off; off.SetInt32(idx); 
                                        cPriv.Add(&off); 
                                    } else { 
                                        Int off; off.SetInt32(idx - 256); 
                                        cPriv.Sub(&off); 
                                    }
                                    
                                    std::string foundPriv = padHexTo64(intToHex(cPriv));
                                    std::string foundPubCompressed = pointToCompressedHex(ptBatch[idx]);
                                    
                                    // Generate uncompressed pubkey untuk display
                                    std::string foundPubUncompressed;
                                    {
                                        uint8_t uncompressed[65];
                                        pointToUncompressedBin(ptBatch[idx], uncompressed);
                                        foundPubUncompressed = "04" + bytesToHex(uncompressed + 1, 64);
                                    }
                                    
                                    // WIF tergantung pada jenis address yang ditemukan
                                    bool isCompressed = (addressType == "Compressed");
                                    std::string foundWIF = P2PKHDecoder::compute_wif(foundPriv, isCompressed);
                                    
                                    std::string hash160Hex = bytesToHex(foundHash, 20);
                                    
                                    std::cout << "\n==== MATCH DARI WALLETS DATA (" << addressType << ") ====\n";
                                    std::cout << "Hash160 : " << hash160Hex << "\n";
                                    std::cout << "PubKey (Compressed)  : " << foundPubCompressed << "\n";
                                    std::cout << "PubKey (Uncompressed): " << foundPubUncompressed << "\n";
                                    std::cout << "Privkey : " << foundPriv << "\n";
                                    std::cout << "WIF     : " << foundWIF << "\n";
                                    std::cout << "Address Type: " << addressType << "\n";
                                    std::cout << "=================================\n";
                                    
                                    sendWalletFoundNotification(foundPriv, foundPubCompressed, foundWIF, hash160Hex);
                                    
                                    #pragma omp atomic
                                    g_walletFound++;
                                    
                                    if (jumpEnabled) ++pendingJumps;
                                }
                                ++localChecked;
                            }
                            localCnt = 0;
                        }
                    }
                    
                    if(jumpEnabled && pendingJumps>0){
                        for(unsigned int pj=0; pj<pendingJumps; ++pj)
                            priv.Add(&jumpInt);              
                        
                        base = secp.ComputePublicKey(&priv);
                        
                        unsigned long long skipped =
                            static_cast<unsigned long long>(pendingJumps) * g_jumpSize;
                        localChecked += skipped;
                        localJumps   += pendingJumps;
                        
                        #pragma omp atomic
                        g_jumpsCount += pendingJumps;
                        
                        pendingJumps = 0;
                        if(intGreater(priv,privEnd)) break;
                    } else {
                        // Langkah normal
                        Int step; step.SetInt32(fullBatch-2);
                        priv.Add(&step);
                        base=secp.AddDirect(base,big512G);
                    }
                    
                    // Cek apakah perlu update statistik
                    auto now=std::chrono::high_resolution_clock::now();
                    if(std::chrono::duration<double>(now-lastStat).count() >= STATUS_INTERVAL_SEC) {
                        #pragma omp critical(stats_update)
                        {
                            globalChecked += localChecked;
                            localChecked = 0ULL;
                            globalElapsed = std::chrono::duration<double>(now - tStart).count();
                            mkeys = globalChecked/globalElapsed/1e6;
                            long double prog = totalRangeLD>0.0L
                                ? (globalChecked/totalRangeLD*100.0L)
                                : 0.0L;
                            
                            printStats(numCPUs, displayRange,
                                       mkeys, globalChecked, globalElapsed,
                                       g_progressSaveCount, prog,
                                       g_walletFound,
                                       jumpEnabled, g_jumpsCount);
                            lastStat = now;
                        }
                    }
                    
                    // Cek apakah perlu save progress
                    if(std::chrono::duration<double>(now-lastSave).count() >= SAVE_PROGRESS_INTERVAL) {
                        #pragma omp critical(save_progress)
                        {
                            if(tid == 0) {
                                // Update statistik global untuk resume
                                #pragma omp atomic update
                                globalChecked += localChecked;
                                localChecked = 0;
                                
                                g_progressSaveCount++;
                                
                                // Persiapkan data resume
                                resumeState.threadPrivKeys = g_threadPrivateKeys;
                                if(randomMode && g_chunkTracker) {
                                    resumeState.processedChunks = g_chunkTracker->processed;
                                } else {
                                    resumeState.processedChunks.clear();
                                }
                                
                                resumeState.totalChecked = globalChecked;
                                resumeState.elapsedTime = globalElapsed;
                                resumeState.jumpSize = g_jumpSize;
                                resumeState.walletFound = g_walletFound;
                                resumeState.jumpsCount = g_jumpsCount;
                                
                                // Simpan state untuk resume
                                {
                                    std::lock_guard<std::mutex> lock(g_saveStateMutex);
                                    saveResumeState("resume.state", resumeState);
                                }
                                
                                // Simpan juga log progress seperti di kode asli
                                auto nowSave = std::chrono::high_resolution_clock::now();
                                double sinceStart = std::chrono::duration<double>(nowSave - tStart).count();
                                
                                std::ostringstream oss;
                                oss << "Progress Save #" << g_progressSaveCount
                                   << " at " << sinceStart << " sec: "
                                   << "TotalChecked=" << globalChecked << ", "
                                   << "ElapsedTime=" << formatElapsedTime(globalElapsed) << ", "
                                   << "Mkeys/s=" << std::fixed << std::setprecision(2)
                                              << mkeys << "\n";
                                for(int k=0; k<numCPUs; ++k) {
                                    oss << "Thread Key " << k << ": " << g_threadPrivateKeys[k] << "\n";
                                }
                                if(randomMode && g_chunkTracker) {
                                    oss << "Chunk yang tersisa: " << g_chunkTracker->remainingChunks 
                                        << " dari " << numChunks << "\n";
                                }
                                saveProgressToFile(oss.str());
                                lastSave = now;
                            }
                        }
                    }
                } // end while dalam chunk
                
                // Update global counter setelah selesai chunk
                #pragma omp critical(global_update)
                {
                    globalChecked += localChecked;
                    localChecked = 0ULL;
                    g_jumpsCount += localJumps;
                    localJumps = 0ULL;
                }
            } // end while chunk random
        } else {
            // Mode sequential seperti di kode asli (dengan beberapa modifikasi untuk resume)
            Int priv = hexToInt(g_threadRanges[tid].startHex);
            
            // Jika resume mode, coba gunakan private key yang tersimpan jika ada
            if(resumeMode && tid < resumeState.threadPrivKeys.size()) {
                std::string savedKey = resumeState.threadPrivKeys[tid];
                if(savedKey != "0") {
                    priv = hexToInt(savedKey);
                    std::cout << "Thread " << tid << " melanjutkan dari key " << savedKey << "\n";
                }
            }
            
            const Int privEnd = hexToInt(g_threadRanges[tid].endHex);
            Point base = secp.ComputePublicKey(&priv);
            
            while(true){
                if(intGreater(priv,privEnd)) break;
                
                #pragma omp critical(update_thread_key)
                g_threadPrivateKeys[tid] = padHexTo64(intToHex(priv));
                
                // --- Kode perhitungan point dan hash sama dengan mode random ---
                for(int i=0;i<POINTS_BATCH_SIZE;++i){
                    deltaX[i].ModSub(&plus[i].x,&base.x);
                }
                modGrp.Set(deltaX.data()); modGrp.ModInv();
                
                for(int i=0;i<POINTS_BATCH_SIZE;++i){
                    Point r=base;
                    Int dY; dY.ModSub(&plus[i].y,&base.y);
                    Int k; k.ModMulK1(&dY,&deltaX[i]);
                    Int k2; k2.ModSquareK1(&k);
                    Int xNew; xNew.Set(&base.x); xNew.ModNeg(); xNew.ModAdd(&k2);
                    xNew.ModSub(&plus[i].x); r.x.Set(&xNew);
                    Int dx; dx.Set(&base.x); dx.ModSub(&r.x); dx.ModMulK1(&k);
                    r.y.ModNeg(); r.y.ModAdd(&dx);
                    ptBatch[i]=r;
                }
                for(int i=0;i<POINTS_BATCH_SIZE;++i){
                    Point r=base;
                    Int dY; dY.ModSub(&minus[i].y,&base.y);
                    Int k; k.ModMulK1(&dY,&deltaX[i]);
                    Int k2; k2.ModSquareK1(&k);
                    Int xNew; xNew.Set(&base.x); xNew.ModNeg(); xNew.ModAdd(&k2);
                    xNew.ModSub(&minus[i].x); r.x.Set(&xNew);
                    Int dx; dx.Set(&base.x); dx.ModSub(&r.x); dx.ModMulK1(&k);
                    r.y.ModNeg(); r.y.ModAdd(&dx);
                    ptBatch[POINTS_BATCH_SIZE+i]=r;
                }
                
                unsigned int pendingJumps=0;

                for (int i = 0; i < fullBatch; ++i) {
                pointToCompressedBin(ptBatch[i], pubKeysCompressed[localCnt]);
                pointToUncompressedBin(ptBatch[i], pubKeysUncompressed[localCnt]);
                idxArr[localCnt] = i;
                ++localCnt;
                
                if (localCnt == HASH_BATCH_SIZE) {
                    // Compute hash160 for both compressed and uncompressed
                    // computeHash160BatchBinSingle(localCnt, pubKeysCompressed, hashResCompressed);
                    // computeHash160BatchBinUncompressed(localCnt, pubKeysUncompressed, hashResUncompressed);
                    computeHash160BatchBinUnified(localCnt, 
                                      pubKeysCompressed, pubKeysUncompressed,
                                      hashResCompressed, hashResUncompressed);
                    
                    for (int j = 0; j < HASH_BATCH_SIZE; ++j) {
                        bool found = false;
                        std::string addressType;
                        const uint8_t* foundHash = nullptr;
                        
                        // Check compressed address
                        if (bloom_check_binary(hashResCompressed[j]) == 1) {
                            found = true;
                            addressType = "Compressed";
                            foundHash = hashResCompressed[j];
                        }
                        // Check uncompressed address  
                        else if (bloom_check_binary(hashResUncompressed[j]) == 1) {
                            found = true;
                            addressType = "Uncompressed";
                            foundHash = hashResUncompressed[j];
                        }
                        
                        if (found) {
                            // WALLET DITEMUKAN!
                            Int cPriv = priv;
                            int idx = idxArr[j];
                            if (idx < 256) { 
                                Int off; off.SetInt32(idx); 
                                cPriv.Add(&off); 
                            } else { 
                                Int off; off.SetInt32(idx - 256); 
                                cPriv.Sub(&off); 
                            }
                            
                            std::string foundPriv = padHexTo64(intToHex(cPriv));
                            std::string foundPubCompressed = pointToCompressedHex(ptBatch[idx]);
                            
                            // Generate uncompressed pubkey untuk display
                            std::string foundPubUncompressed;
                            {
                                uint8_t uncompressed[65];
                                pointToUncompressedBin(ptBatch[idx], uncompressed);
                                foundPubUncompressed = "04" + bytesToHex(uncompressed + 1, 64);
                            }
                            
                            // WIF tergantung pada jenis address yang ditemukan
                            bool isCompressed = (addressType == "Compressed");
                            std::string foundWIF = P2PKHDecoder::compute_wif(foundPriv, isCompressed);
                            
                            std::string hash160Hex = bytesToHex(foundHash, 20);
                            
                            std::cout << "\n==== MATCH DARI WALLETS DATA (" << addressType << ") ====\n";
                            std::cout << "Hash160 : " << hash160Hex << "\n";
                            std::cout << "PubKey (Compressed)  : " << foundPubCompressed << "\n";
                            std::cout << "PubKey (Uncompressed): " << foundPubUncompressed << "\n";
                            std::cout << "Privkey : " << foundPriv << "\n";
                            std::cout << "WIF     : " << foundWIF << "\n";
                            std::cout << "Address Type: " << addressType << "\n";
                            std::cout << "=================================\n";
                            
                            sendWalletFoundNotification(foundPriv, foundPubCompressed, foundWIF, hash160Hex);
                            
                            #pragma omp atomic
                            g_walletFound++;
                            
                            if (jumpEnabled) ++pendingJumps;
                        }
                        ++localChecked;
                    }
                    localCnt = 0;
                }
            }
                
                if(jumpEnabled && pendingJumps>0){
                    for(unsigned int pj=0; pj<pendingJumps; ++pj)
                        priv.Add(&jumpInt);              
                    
                    base = secp.ComputePublicKey(&priv);
                    
                    unsigned long long skipped =
                        static_cast<unsigned long long>(pendingJumps) * g_jumpSize;
                    localChecked += skipped;
                    localJumps   += pendingJumps;
                    
                    #pragma omp atomic
                    g_jumpsCount += pendingJumps;
                    
                    pendingJumps  = 0;
                    if(intGreater(priv,privEnd)) break;
                }
                
                // Langkah normal
                {
                    Int step; step.SetInt32(fullBatch-2);
                    priv.Add(&step);
                    base=secp.AddDirect(base,big512G);
                }
                
                // Cek apakah perlu update statistik
                auto now=std::chrono::high_resolution_clock::now();
                if(std::chrono::duration<double>(now-lastStat).count() >= STATUS_INTERVAL_SEC) {
                    #pragma omp critical(stats_update)
                    {
                        globalChecked += localChecked;
                        localChecked = 0ULL;
                        globalElapsed = std::chrono::duration<double>(now - tStart).count();
                        mkeys = globalChecked/globalElapsed/1e6;
                        long double prog = totalRangeLD>0.0L
                            ? (globalChecked/totalRangeLD*100.0L)
                            : 0.0L;
                        
                        printStats(numCPUs, displayRange,
                                   mkeys, globalChecked, globalElapsed,
                                   g_progressSaveCount, prog,
                                   g_walletFound,
                                   jumpEnabled, g_jumpsCount);
                        lastStat = now;
                    }
                }
                
                // Cek apakah perlu save progress untuk resume
                if(std::chrono::duration<double>(now-lastSave).count() >= SAVE_PROGRESS_INTERVAL) {
                    #pragma omp critical(save_progress)
                    {
                        if(tid == 0) {
                            // Update statistik global
                            #pragma omp atomic update
                            globalChecked += localChecked;
                            localChecked = 0;
                            
                            g_progressSaveCount++;
                            
                            // Persiapkan data resume
                            resumeState.threadPrivKeys = g_threadPrivateKeys;
                            resumeState.processedChunks.clear(); // Mode sekuensial tidak perlu chunk info
                            resumeState.totalChecked = globalChecked;
                            resumeState.elapsedTime = globalElapsed;
                            resumeState.jumpSize = g_jumpSize;
                            resumeState.walletFound = g_walletFound;
                            resumeState.jumpsCount = g_jumpsCount;
                            
                            // Simpan state untuk resume
                            {
                                std::lock_guard<std::mutex> lock(g_saveStateMutex);
                                saveResumeState("resume.state", resumeState);
                            }
                            
                            // Simpan juga log progress seperti di kode asli
                            auto nowSave = std::chrono::high_resolution_clock::now();
                            double sinceStart = std::chrono::duration<double>(nowSave - tStart).count();
                            
                            std::ostringstream oss;
                            oss << "Progress Save #" << g_progressSaveCount
                               << " at " << sinceStart << " sec: "
                               << "TotalChecked=" << globalChecked << ", "
                               << "ElapsedTime=" << formatElapsedTime(globalElapsed) << ", "
                               << "Mkeys/s=" << std::fixed << std::setprecision(2)
                                         << mkeys << "\n";
                            for(int k=0; k<numCPUs; ++k) {
                                oss << "Thread Key " << k << ": " << g_threadPrivateKeys[k] << "\n";
                            }
                            saveProgressToFile(oss.str());
                            lastSave = now;
                        }
                    }
                }
            } // end while sequential
        }
        
        // Akumulasikan keys yang telah dicek
        #pragma omp atomic
        globalChecked += localChecked;
    } /* omp parallel */
    
    // Bersihkan alokasi memori
    if(g_chunkTracker) {
        delete g_chunkTracker;
        g_chunkTracker = nullptr;
    }

    std::cout<<"\nPencarian selesai. Ditemukan "<<g_walletFound<<" wallet.\n";
    return 0;
}