# AES-128 Cipher Visualizer

## Cara Menjalankan

### 1. Install dependensi
```bash
pip install flask
```

### 2. Jalankan server
```bash
python app.py
```

### 3. Buka browser
```
http://localhost:5000
```

## Struktur File

```
aes_app/
├── app.py          # Flask backend server
├── aes_core.py     # Implementasi AES-128 lengkap dengan logging step-by-step
├── index.html      # Frontend HTML/CSS/JS modern
└── README.md       # Panduan ini
```

## Fitur

- ✅ Enkripsi & Dekripsi AES-128 (ECB mode)
- ✅ Input: teks (maks 16 char) atau 32 hex untuk enkripsi; 32 hex untuk dekripsi  
- ✅ Key Expansion lengkap: W[0]–W[43] + fungsi g (RotWord, SubWord, XOR Rcon)
- ✅ Round Keys RK0–RK10 dalam format tabel 4×4
- ✅ Visualisasi state matrix 4×4 setiap operasi dengan warna berbeda
- ✅ Detail per ronde: SubBytes, ShiftRows, MixColumns, AddRoundKey
- ✅ Dekripsi: InvShiftRows, InvSubBytes, InvMixColumns
- ✅ Toggle tampilkan/sembunyikan detail
- ✅ Copy output ke clipboard
- ✅ Navigasi antar ronde (breadcrumb/nav pills)
- ✅ Highlight sel yang berubah antar state matrix
- ✅ Responsif desktop & mobile

## Test Vector
- Key: `2b7e151628aed2a6abf7158809cf4f3c`
- Plaintext (hex): `00112233445566778899aabbccddeeff`  
- Ciphertext: `69c4e0d86a7b0430d8cdb78070b4c55a`
