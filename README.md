# Brutus - Bitcoin Private Key Range Scanner

Brutus adalah program kriptografi untuk mencari private key dari alamat Bitcoin dengan melakukan scanning pada range kunci tertentu. Program ini dioptimalkan dengan AVX2 dan OpenMP untuk mencapai kecepatan pemindaian maksimal.

## Deskripsi

Program ini mencari private key Bitcoin dengan:
- Memeriksa range private key yang ditentukan
- Mendukung pengecekan partial hash (prefix matching)
- Menggunakan pemrosesan batch untuk komputasi hash
- Mendukung mode pencarian acak dan sekuensial
- Mendukung pencarian terfokus pada sebagian range

## Prasyarat

- GCC/G++ dengan dukungan C++17
- Prosesor yang mendukung AVX2 (CPU Intel generasi Haswell ke atas atau AMD setara)
- OpenMP
- Minimal 2GB RAM (direkomendasikan 4GB+)

## Instalasi

### Linux

1. Pastikan Anda memiliki build tools yang diperlukan:
   ```bash
   sudo apt-get update
   sudo apt-get install build-essential g++ make
   ```

2. Clone atau download source code

3. Kompilasi:
   ```bash
   make
   ```

### Windows

1. Instal MSYS2 dari [https://www.msys2.org/](https://www.msys2.org/)

2. Instal paket yang diperlukan melalui MSYS2:
   ```bash
   pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-make
   ```

3. Tambahkan `C:\msys64\mingw64\bin` ke PATH sistem

4. Clone atau download source code

5. Atau jalankan Terminal Programnya di C:\msys64\ucrt64.exe

5. Kompilasi:
   Pastikan Terlebih dahulu masuk ke direktory/folder Projectnya
   
   ```bash
   mingw32-make
   ```
   atau 

   ```bash
   make clear
   make
   ```

## Penggunaan

### Parameter Wajib
- `-r <start:end>` : Range pencarian dalam format hexadecimal

### Parameter Opsional

- `-p <HEXLEN>` : Panjang prefix HASH160 (dalam hex) yang harus cocok (1-40)
- `-j <JUMP>` : Nilai jump saat menemukan kandidat (memerlukan parameter -p)
- `-s` : Simpan kandidat yang ditemukan ke file
- `-f <START%:END%>` : Fokus pencarian pada persentase tertentu dari range (mis. 32:33 untuk 1% range)
- `-random` : Gunakan mode pencarian acak (dengan sistem chunk)
- `-chunks <NUM>` : Jumlah chunk untuk mode random (default: 1000)
- `-resume` : Lanjutkan pencarian dari state terakhir yang disimpan

### Contoh Penggunaan

#### Pencarian Dasar
```bash
./brutus -r 10000000000:1ffffffffff
```

#### Pencarian dengan Fokus pada 1% Range (antara 32%-33%)
```bash
./brutus -r 10000000000:1ffffffffff -f 32:33
```

#### Pencarian dengan Mode Acak
```bash
./brutus -r 10000000000:1ffffffffff -random
```

#### Pencarian Partial dengan Jump
```bash
./brutus -r 10000000000:1ffffffffff -p 8 -j 1000000
```

#### Melanjutkan Pencarian
```bash
./brutus -r 10000000000:1ffffffffff -resume
```

#### Mode Full
```bash
./brutus -r 10000000000:1ffffffffff -f 32:33 -random -resume -chunks 20000
```

## Fitur Detail

### Mode Pencarian

1. **Sekuensial (default)**:
   - Range dibagi rata antar thread
   - Setiap thread memproses bagiannya secara berurutan

2. **Random (-random)**:
   - Range dibagi menjadi chunk-chunk kecil (default: 1000)
   - Thread mengambil chunk secara acak untuk pemrosesan
   - Berguna untuk eksplorasi yang lebih merata saat waktu pencarian terbatas

### Fitur Resume

Program menyimpan state pencarian setiap 5 menit ke file `resume.state`. Untuk melanjutkan pencarian dari titik terakhir, gunakan parameter `-resume`.

### Fitur Fokus Range (-f)

Memungkinkan fokus pencarian pada subset persentase tertentu dari total range, berguna untuk membagi pencarian besar menjadi bagian-bagian yang lebih kecil dan dapat dikelola.

### Fitur Jump (-j)

Ketika kandidat ditemukan (dengan parameter `-p`), program dapat melompat sejumlah kunci untuk mempercepat pencarian. Memerlukan parameter `-p` untuk menentukan prefiks yang cocok.

## Output

Program menampilkan informasi progress:
- Target address dan hash160
- Kecepatan pencarian (Mkeys/s)
- Total kunci yang diperiksa
- Waktu yang telah berlalu
- Persentase kemajuan
- Jumlah kandidat dan jump (jika fitur tersebut diaktifkan)

Jika ditemukan kecocokan penuh, program akan menampilkan:
- Private key (format hex)
- Public key (format compressed hex)
- WIF (Wallet Import Format)
- Alamat P2PKH

## File Output

- `candidates.txt`: Daftar kandidat jika parameter `-s` digunakan
- `progress.txt`: Log kemajuan pencarian
- `resume.state`: File binary untuk fitur resume

## Catatan Performa

- Performa optimal dicapai pada CPU dengan dukungan AVX2 yang baik
- Batasan konstanta `HASH_BATCH_SIZE` (8) dioptimalkan untuk implementasi AVX2 saat ini
- Penggunaan memori meningkat dengan jumlah thread

## Troubleshooting

- Jika mengalami crash, coba kurangi jumlah thread
- Jika performa rendah, pastikan CPU mendukung AVX2
- Jika mengalami error kompilasi, pastikan versi GCC/G++ mendukung C++17

## Keamanan dan Pertimbangan Etis

Program ini ditujukan untuk tujuan edukasi, pengembangan, dan pemulihan dompet Bitcoin yang hilang. Menggunakan alat ini untuk mencoba mengakses dompet orang lain tanpa izin adalah ilegal.

## Third-Party Code

Script ini pengembangan dari Repository [Cyclone](https://github.com/Dookoo2/Cyclone).
