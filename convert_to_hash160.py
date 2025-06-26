import hashlib
import base58
import re

def address_to_hash160(address):
    try:
        # Decode base58 (menghilangkan checksum dan version)
        decoded = base58.b58decode_check(address)
        # Hash160 adalah 20 byte setelah version (byte ke-1 sampai ke-21)
        return decoded[1:21].hex()
    except Exception as e:
        print(f"[ERROR] {address}: {e}")
        return None

# Baca file alamat Bitcoin (setiap baris = 1 address)
with open('Bitcoin_addresses_LATEST.txt', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Tulis hasil hash160 ke file output
with open('wallets_hash160.txt', 'w', encoding='utf-8', newline='\n') as f:
    for line in lines:
        # Hapus semua karakter whitespace termasuk \r, \n, \t, dan spasi
        address = re.sub(r'\s+', '', line)

        # Filter hanya alamat P2PKH (prefix '1')
        if address.startswith('1'):
            hash160 = address_to_hash160(address)
            if hash160:
                f.write(f"{hash160}\n")
            else:
                print(f"[SKIP] Gagal konversi: {address}")
        else:
            # Lewati P2SH (prefix '3') dan Bech32 (prefix 'bc1')
            continue
