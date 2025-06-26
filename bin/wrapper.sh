#!/bin/bash

# wrapper.sh - Script untuk menjalankan Brutus Bitcoin Key Scanner sebagai service
# -----------------------------------------------------------------------------------------

# Direktori instalasi Brutus (ubah sesuai lokasi instalasi Anda)
BRUTUS_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$BRUTUS_DIR" || {
    echo "ERROR: Tidak dapat mengakses direktori Brutus: $BRUTUS_DIR"
    exit 1
}

# -----------------------------------------------------------------------------------------
# KONFIGURASI - UBAH SESUAI KEBUTUHAN ANDA
# -----------------------------------------------------------------------------------------

# Parameter pencarian (wajib diisi)

#20000000:ffffffffffffffffffffffffffffffffffffffff # adalah entropy bit 30 sampai bit 160
RANGE="1000000000000000000000000000000000000000000000000000000000000000:fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140" 
BIT_AREA="256:256"          # Rentang bit untuk pencarian (format: start:end)
# Parameter opsional
FOCUS="0:100"                # Rentang fokus (format: start%:end%)
NUM_CHUNKS="50000"            # Jumlah chunk untuk mode random
USE_RANDOM_MODE="yes"        # Gunakan mode random (yes/no)
SAVE_CANDIDATES="no"         # Simpan kandidat (yes/no)
PREFIX_LEN=""                # Panjang prefix HASH160 (kosongkan jika tidak digunakan) 
JUMP_SIZE=""                 # Ukuran jump (kosongkan jika tidak digunakan)

# Parameter output dan logging
LOG_FILE="cireng.log"       # File log utama
ERR_LOG_FILE="cireng.err"   # File log error
APPEND_LOGS="yes"            # Tambahkan ke log yang ada (yes/no)
LOG_LEVEL="normal"           # normal/debug/trace

# -----------------------------------------------------------------------------------------
# FUNGSI
# -----------------------------------------------------------------------------------------

# Fungsi untuk logging
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
    
    # Jika level ERROR, juga menulis ke file error
    if [[ "$level" == "ERROR" ]]; then
        echo "[$timestamp] [$level] $message" >> "$ERR_LOG_FILE"
    fi
}

# Fungsi untuk membersihkan saat exit
cleanup() {
    log "INFO" "Menerima signal untuk berhenti, membersihkan..."
    
    # Cek apakah ada PID Brutus yang perlu dihentikan
    if [[ -n "$BRUTUS_PID" ]]; then
        log "INFO" "Menghentikan proses Brutus (PID: $BRUTUS_PID)"
        kill -INT "$BRUTUS_PID" 2>/dev/null
        
        # Tunggu proses selesai dengan timeout
        local timeout=10
        while kill -0 "$BRUTUS_PID" 2>/dev/null && [ $timeout -gt 0 ]; do
            sleep 1
            ((timeout--))
        done
        
        # Force kill jika masih berjalan
        if kill -0 "$BRUTUS_PID" 2>/dev/null; then
            log "WARNING" "Brutus tidak merespon, melakukan force kill"
            kill -9 "$BRUTUS_PID" 2>/dev/null
        fi
    fi
    
    log "INFO" "Proses pembersihan selesai, keluar dengan status $1"
    exit "$1"
}

# -----------------------------------------------------------------------------------------
# INISIALISASI
# -----------------------------------------------------------------------------------------

# Setup file log
if [[ "$APPEND_LOGS" != "yes" ]]; then
    # Buat backup log sebelumnya jika perlu
    if [[ -f "$LOG_FILE" ]]; then
        mv "$LOG_FILE" "${LOG_FILE}.$(date '+%Y%m%d%H%M%S').bak"
    fi
    if [[ -f "$ERR_LOG_FILE" ]]; then
        mv "$ERR_LOG_FILE" "${ERR_LOG_FILE}.$(date '+%Y%m%d%H%M%S').bak"
    fi
    
    # Reset file log
    > "$LOG_FILE"
    > "$ERR_LOG_FILE"
fi

# Log informasi awal
log "INFO" "==============================================="
log "INFO" "Cireng Bitcoin Key Scanner Wrapper"
log "INFO" "Mulai pada: $(date)"
log "INFO" "System: $(uname -a)"
log "INFO" "Direktori: $BRUTUS_DIR"
log "BIT Area: $BIT_AREA"
log "INFO" "==============================================="

# Tangkap signal
trap 'cleanup 1' INT TERM
trap 'log "ERROR" "Received signal SIGABRT or SEGFAULT"; cleanup 2' ABRT SEGV

# Periksa apakah executable ada
if [[ ! -x "./cireng" ]] && [[ ! -x "./cireng.exe" ]]; then
    log "ERROR" "Executable Brutus tidak ditemukan atau tidak executable"
    exit 1
fi

# Tentukan executable berdasarkan platform
BRUTUS_EXE="./cireng"
if [[ -f "./cireng.exe" ]]; then
    BRUTUS_EXE="./cireng.exe"
fi

# -----------------------------------------------------------------------------------------
# MEMBANGUN COMMAND LINE
# -----------------------------------------------------------------------------------------

# Mulai dengan parameter wajib
CMD="$BRUTUS_EXE -r $RANGE -resume"

# Tambahkan parameter opsional jika diisi
if [[ -n "$FOCUS" ]]; then
    CMD="$CMD -f $FOCUS"
fi

if [[ "$USE_RANDOM_MODE" == "yes" ]]; then
    CMD="$CMD -random -chunks $NUM_CHUNKS"
fi

if [[ "$SAVE_CANDIDATES" == "yes" ]]; then
    CMD="$CMD -s"
fi

if [[ -n "$PREFIX_LEN" ]]; then
    CMD="$CMD -p $PREFIX_LEN"
    
    # Tambahkan jump size jika ada
    if [[ -n "$JUMP_SIZE" ]]; then
        CMD="$CMD -j $JUMP_SIZE"
    fi
fi

# Log command yang akan dijalankan
log "INFO" "Menjalankan command: $CMD"

# -----------------------------------------------------------------------------------------
# EKSEKUSI Brutus
# -----------------------------------------------------------------------------------------

# Jalankan Brutus
eval "$CMD" &
BRUTUS_PID=$!

log "INFO" "Cireng berjalan dengan PID: $BRUTUS_PID"


# Tunggu proses Brutus selesai
wait $BRUTUS_PID
BRUTUS_EXIT_CODE=$?

# Log hasil eksekusi
if [[ $BRUTUS_EXIT_CODE -eq 0 ]]; then
    log "INFO" "Cireng selesai dengan sukses (kode: $BRUTUS_EXIT_CODE)"
    exit 0
else
    log "WARNING" "Cireng keluar dengan kode error: $BRUTUS_EXIT_CODE"
    
    # Tunggu beberapa saat sebelum restart
    log "INFO" "Menunggu 5 detik sebelum restart..."
    sleep 5
    
    # Keluar dengan kode 1 agar systemd me-restart
    exit 1
fi