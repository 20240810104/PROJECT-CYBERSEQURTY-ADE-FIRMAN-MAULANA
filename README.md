# 📦 Secure Inventory Management Web App (Sistem Inventaris Gudang Aman)

[![Cyber Security](https://img.shields.io/badge/Subject-Cyber%20Security-blue.svg)](https://uniku.ac.id)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.1-black.svg)](https://flask.palletsprojects.com/)
[![OWASP Top 10](https://img.shields.io/badge/Security-OWASP%20Hardened-success.svg)](https://owasp.org)
[![License](https://img.shields.io/badge/License-Academic%20Project-orange.svg)](#)

> **Tugas Project: Pengembangan & Pengamanan Aplikasi Web**  
> **Mata Kuliah:** Cyber Security  
> **Program Studi:** S1 Teknik Informatika — Universitas Kuningan (UNIKU)  
> **Format Pengumpulan:** URL Aplikasi, URL Repository Git, dan Laporan PDF (EdLink)  

---

## 👤 Identitas Pengembang
- **Nama Mahasiswa :** Ade Firman Maulana
- **NIM             :** 20240810104
- **Kelas           :** TINFC-2024-03
- **Repository      :** [https://github.com/20240810104](https://github.com/20240810104)

---

## 1. 📝 Deskripsi Proyek
Aplikasi ini adalah **Sistem Informasi Manajemen Inventaris Barang Gudang** yang dibangun dengan mengedepankan prinsip **Security-by-Design** dan pengerasan keamanan web berbasis panduan standar **OWASP Top 10**. 

Aplikasi memungkinkan pencatatan siklus barang secara terintegrasi (pencatatan barang masuk/keluar, update stok, pelaporan CSV, visualisasi grafik) sekaligus menjaga data dari potensi kebocoran, eksploitasi injeksi, pembajakan sesi, dan manipulasi transaksi lintas situs.

### 🎓 Potensi Pengembangan ke Skripsi (Tingkat 4)
Aplikasi ini dirancang sebagai fondasi penelitian tingkat akhir dengan topik yang relevan:
> *"Implementasi Arsitektur Web Zero-Trust dan Algoritma Single Exponential Smoothing untuk Prediksi Kebutuhan Inventaris dan Audit Keamanan Rantai Pasok"*.

---

## 2. 🚀 Fitur Utama Sistem

### A. Pengelolaan Data & Pemisahan Peran (RBAC)
- **Role Administrator (👑 Admin):**
  - **Create Master Data :** Menambahkan komoditas barang baru ke katalog master inventaris.
  - **Update Master Data :** Mengubah nama dan deskripsi barang.
  - **Delete Data        :** Menghapus barang permanen (dilengkapi konfirmasi interaktif & pembersihan riwayat mutasi terkait secara aman).
  - **Audit Log Keamanan :** Melihat rekaman jejak audit forensik aktivitas pengguna.
  - **Manajemen Stok     :** Melakukan update & restock kuantitas stok barang.
  - **Laporan Resmi PDF  :** Mengunduh dokumen resmi laporan stok dalam format PDF.
- **Role Petugas Gudang (👷 Petugas):**
  - **Operasional Restock :** Menambahkan restock kuantitas barang masuk untuk barang yang sudah terdaftar.
  - **Pembaruan Stok      :** Melakukan pencatatan mutasi kuantitas keluar/masuk.
  - **Restriksi Ketat     :** **Dilarang keras** menambahkan master barang baru, mengubah data master, maupun menghapus barang (otomatis diblokir dengan HTTP 403 Forbidden via decorator `@admin_required`).
  - **Laporan Resmi PDF  :** Dapat mengunduh dokumen resmi laporan stok PDF.

### B. Fitur Laporan 3-in-1 (Poin 3a Modul)
1. **Tabel Rekapitulasi :** Kartu statistik total jenis barang, total kuantitas stok, dan peringatan stok kritis (≤ 5 unit).
2. **Visualisasi Data Dinamis (Chart.js):**
   - **Bar Chart :** Perbandingan sisa stok per komoditas dengan palet warna dinamis (Merah jika ≤ 5, Biru jika aman).
   - **Doughnut Chart :** Rasio total akumulasi mutasi barang masuk vs keluar.
   - **Line Chart :** Analisis tren temporal transaksi mutasi stok mutakhir.
3. **Ekspor Dokumen Resmi (PDF & CSV):**
   - **Format PDF (Utama):** Unduh dokumen formal `Laporan_Inventaris_Stok.pdf` yang di-generate langsung dari server via engine ReportLab lengkap dengan kop laporan, metadata operator, ringkasan sisa stok, dan riwayat mutasi.
   - **Format CSV (Alternatif):** Tersedia opsi ekspor berkas tabular CSV untuk kebutuhan olah data spreadsheet lanjutan.

---

## 3. 🛡️ Implementasi Aspek Keamanan (Cyber Security Hardening)

| Vektor Keamanan | Implementasi Teknis pada Source Code | Ancaman yang Dicegah |
|---|---|---|
| **Password Hashing** | Algoritma `bcrypt` dengan per-user salt dinamis (`bcrypt.gensalt()`) | Pembacaan kredensial jika database bocor (*anti-rainbow table*). |
| **Password Complexity** | Validasi ekspresi reguler (Regex): min. 8 karakter, huruf besar, kecil, angka, simbol | Serangan kamus (*Dictionary Attack*) dan tebakan kata sandi lemah. |
| **SQL Injection (SQLi)** | Parameterized Queries & Object-Relational Mapping via `SQLAlchemy` | Eksekusi perintah SQL liar pada form login, pencarian, dan parameter URL. |
| **Cross-Site Scripting (XSS)** | Sanitasi input ketat & auto-escaping HTML entity pada Jinja2 template engine | Penyusupan script JavaScript berbahaya (*Stored & Reflected XSS*). |
| **CSRF Protection** | Token anti-CSRF kriptografis per sesi (`secrets.token_hex(32)`) diverifikasi dengan `hmac.compare_digest` | Pemalsuan eksekusi mutasi data dari situs pihak ketiga (*Cross-Site Request Forgery*). |
| **Anti Brute-Force** | Rate limiter in-memory: batas maks. 5x kegagalan berturut-turut, lockout 60 detik | Serangan *Credential Stuffing* dan otomatisasi tebakan kata sandi. |
| **Role-Based Access Control (RBAC)** | Decorator `@admin_required` memisahkan otorisasi role `admin` vs `petugas` | Pembobolan hak akses (*Privilege Escalation* & *Broken Access Control*). |
| **Audit Logging** | Model `AuditLog` mencatat LOGIN_OK, LOGIN_FAIL, BLOCKED, CSRF_BLOCKED, TAMBAH, EDIT, HAPUS | Memenuhi prinsip akuntabilitas (*Non-repudiation*) dan bukti investigasi forensik. |
| **HTTP Security Headers** | `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy`, `Referrer-Policy` | Serangan Clickjacking (iframe abuse), MIME-sniffing, dan injeksi skrip eksternal. |
| **Session Security** | Cookie `HttpOnly`, `SameSite=Lax`, rotasi token CSRF setelah login, masa berlaku sesi 60 menit | Pencurian sesi via script browser (*Session Hijacking* & *Session Fixation*). |

---

## 4. 🧪 Hasil Self-Testing Keamanan (Poin 3f Dokumen Tugas)

Pengujian keamanan dilakukan secara mandiri menggunakan skrip audit otomatis [`test_security.py`](test_security.py) & [`run_detailed_pdf_test.py`](run_detailed_pdf_test.py):

```text
=========================================================================================================
  TABEL HASIL SELF-TESTING KEAMANAN (AUDIT KEPATUHAN OWASP TOP 10)
=========================================================================================================
No  | Kategori Serangan          | Skenario Pengujian                 | Metode Uji / Payload                  | Status Uji
---------------------------------------------------------------------------------------------------------
1   | SQL Injection (SQLi)       | Bypass autentikasi login           | Payload: ' OR '1'='1' --              | LOLOS (SECURE)
2   | Cross-Site Scripting (XSS) | Injeksi skrip pada nama barang     | Payload: <script>alert(1)</script>    | LOLOS (SECURE)
3   | Broken Access Control      | Petugas akses audit & tambah baru  | Sesi Petugas memanggil endpoint Admin | LOLOS (SECURE)
4   | Password Policy            | Pendaftaran password lemah         | Sandi '123456' / 'password'           | LOLOS (SECURE)
5   | Brute-Force Rate Limiting  | Serangan tebakan berulang          | 5x password salah berturut-turut      | LOLOS (SECURE)
6   | Proteksi CSRF              | Mutasi data tanpa token CSRF       | POST /tambah_barang tanpa token       | LOLOS (SECURE)
7   | HTTP Security Headers      | Analisis header respon OWASP       | Inspeksi X-Frame-Options, nosniff, CSP| LOLOS (SECURE)
8   | Integritas Data (CRUD)     | Siklus lengkap data barang & stok  | Uji Create, Read, Update, Delete      | LOLOS (BERFUNGSI)
9   | Restock & Ekspor PDF       | Restock Petugas & Generate PDF     | POST /restock_barang & GET /laporan_pdf| LOLOS (BERFUNGSI)
=========================================================================================================
KESIMPULAN: 9 DARI 9 SKENARIO LOLOS 100% (ZERO CRITICAL VULNERABILITY)
=========================================================================================================
```

> Dokumen pengujian lengkap dalam format PDF formal tersedia di:  
> 📄 [**`Laporan_Pentest_Keamanan.pdf`**](Laporan_Pentest_Keamanan.pdf)

---

## 5. 🛠️ Arsitektur & Teknologi

- **Bahasa Pemrograman :** Python 3
- **Framework Web       :** Flask 3.1
- **Database            :** SQLite dengan SQLAlchemy ORM
- **Kriptografi & Auth  :** Bcrypt, Secrets, HMAC, Regex
- **Frontend / Tampilan :** HTML5, CSS3, Bootstrap 5.3, Bootstrap Icons
- **Visualisasi Data    :** Chart.js 4.4
- **WSGI Production     :** Gunicorn 23.0

---

## 6. 💻 Panduan Instalasi & Menjalankan Lokal

```bash
# 1. Clone repositori ini
git clone https://github.com/20240810104/inventory_secure_web.git
cd inventory_secure_web

# 2. Buat dan aktifkan virtual environment
python -m venv env
# Windows:
.\env\Scripts\activate
# Linux/macOS:
source env/bin/activate

# 3. Install seluruh library dependensi
pip install -r requirements.txt

# 4. Konfigurasi file environment
# Buat file .env dari template .env.example
cp .env.example .env

# 5. Jalankan server lokal
python app.py
```
Akses sistem di browser: **`http://127.0.0.1:5000`**

---

## 7. ⚙️ Konfigurasi Environment Variable (`.env.example`)

Untuk keamanan, file `.env` asli **tidak pernah di-commit ke Git** (dilindungi oleh `.gitignore`). Gunakan template berikut:

```env
# Kunci rahasia enkripsi sesi & token CSRF (gunakan string acak minimal 32 karakter)
SECRET_KEY=kunci_rahasia_super_aman_untuk_enkripsi_sesi_inventaris_2026

# Mode aplikasi (development / production)
FLASK_ENV=production

# Atur True jika dideploy pada server ber-HTTPS
SESSION_COOKIE_SECURE=False
```

---

## 8. 🤖 Laporan Penggunaan AI Agent (Poin 3e Ketentuan Tugas)

Sesuai ketentuan Poin 3e tugas, penggunaan asisten AI dilaporkan secara transparan:

- **Alat AI yang Digunakan :** Google Antigravity Agent (Gemini & Claude).
- **Cakupan Bantuan AI     :**
  1. Perancangan skema rate limiting berbasis IP + username & middleware validasi CSRF HMAC.
  2. Pembangunan skrip audit keamanan otomatis (`test_security.py` & `run_detailed_pdf_test.py`).
  3. Konfigurasi HTTP Security Headers respons OWASP dan styling antarmuka Bootstrap 5 + Chart.js.
- **Contoh Prompt Utama :**
  - *"Tambahkan Keamanan Ekstra: Rate Limiting (Pencegahan Brute-Force) dengan batas 5 kali gagal dan lockout 1 menit."*
  - *"Tambahkan Proteksi CSRF (Cross-Site Request Forgery) untuk mengamankan seluruh request mutasi data."*
  - *"Tambahkan Visualisasi Data (Grafik / Chart Dashboard) menggunakan Chart.js untuk rekap stok dan tren mutasi barang."*
- **Metode Verifikasi Mahasiswa :** Seluruh kode ditinjau langsung (*manual code review*), diuji eksekusinya menggunakan unit test otomatis, serta dipastikan tidak ada rahasia atau database asli yang terekspos ke repositori publik.

---

## 9. 🔑 Akun Uji Coba untuk Dosen Penguji

| Role Akun | Username | Password | Deskripsi Hak Akses |
|---|---|---|---|
| **Administrator** | `admin` | `admin` (atau `admin123`) | **Akses Penuh:** Kelola CRUD Barang, Tambah Komoditas Baru, Edit Master, Hapus Barang, Audit Log, Update/Restock Stok, Ekspor PDF. |
| **Petugas Gudang** | Dapat didaftarkan via menu `/register` | *Kombinasi sandi kuat (min 8 char, uppercase, number, symbol)* | **Akses Operasional:** Menambahkan Restock Barang Masuk, Update Stok, Ekspor PDF (Dibatasi ketat dari tambah master barang baru, edit master, hapus, dan audit log). |
