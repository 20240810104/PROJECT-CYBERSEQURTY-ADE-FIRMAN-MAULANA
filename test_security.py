"""
=============================================================================
SELF-TESTING KEAMANAN APLIKASI WEB INVENTARIS
Sesuai Ketentuan Tugas Project Cyber Security (Poin 3f)
=============================================================================
Skrip pengujian otomatis untuk memvalidasi:
1. SQL Injection (SQLi)
2. Cross-Site Scripting (XSS)
3. Broken Access Control / Kontrol Akses Berbasis Peran (RBAC)
4. Kompleksitas Password (Password Policy)
5. Rate Limiting (Pencegahan Serangan Brute-Force)
6. Cross-Site Request Forgery (CSRF Protection)
7. HTTP Security Headers & Cookie Security
8. Integritas Pengelolaan Data (CRUD Lengkap)
=============================================================================
"""

import sys
import os
import json
from datetime import datetime
from app import app, db, User, Barang, RiwayatStok

def run_tests():
    print("=" * 75)
    print("  MEMULAI SELF-TESTING KEAMANAN SISTEM INVENTARIS")
    print(f"  Waktu Pengujian : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 75)

    results = []

    with app.test_client() as client:
        # Persiapan Session & CSRF Token
        res_init = client.get('/login')
        with client.session_transaction() as sess:
            valid_csrf = sess.get('csrf_token')

        # ---------------------------------------------------------------------
        # SKENARIO 1: SQL Injection (SQLi) pada Formulir Login
        # ---------------------------------------------------------------------
        sqli_payload = "' OR '1'='1' --"
        res_sqli = client.post('/login', data={
            'username': sqli_payload,
            'password': 'anypassword',
            'csrf_token': valid_csrf
        })
        # Harus gagal login (tidak boleh bypass autentikasi)
        sqli_passed = (res_sqli.status_code == 200 and "Username atau password salah" in res_sqli.data.decode('utf-8'))
        results.append({
            'no': 1,
            'skenario': 'SQL Injection (SQLi) Bypass Login',
            'metode': f"Injeksi payload '{sqli_payload}' pada form username login",
            'ekspektasi': 'Autentikasi ditolak; tidak terjadi bypass database',
            'status': 'LOLOS (SECURE)' if sqli_passed else 'GAGAL'
        })

        # ---------------------------------------------------------------------
        # SKENARIO 2: Cross-Site Scripting (XSS) Sanitasi Input Barang
        # ---------------------------------------------------------------------
        # Login sebagai admin terlebih dahulu
        with client.session_transaction() as sess:
            sess_csrf = sess.get('csrf_token')
        client.post('/login', data={'username': 'admin', 'password': 'admin', 'csrf_token': sess_csrf})

        xss_payload = "<script>alert('XSS_ATTACK_TEST')</script>"
        res_tambah = client.post('/tambah_barang', data={
            'nama_barang': xss_payload,
            'deskripsi': 'Uji coba injeksi script',
            'csrf_token': sess_csrf
        }, follow_redirects=True)

        body_html = res_tambah.data.decode('utf-8')
        # Payload harus di-escape oleh Jinja2 (muncul sebagai &lt;script&gt; atau tidak dieksekusi)
        # Khususnya tidak boleh dirender mentah tanpa escaping di HTML tabel
        xss_passed = ("&lt;script&gt;alert(" in body_html or xss_payload not in body_html)
        results.append({
            'no': 2,
            'skenario': 'Stored Cross-Site Scripting (XSS)',
            'metode': f"Injeksi tag HTML/JS '{xss_payload}' pada nama barang",
            'ekspektasi': 'Input disanitasi & di-escape otomatis (HTML entity); skrip tidak aktif',
            'status': 'LOLOS (SECURE)' if xss_passed else 'GAGAL'
        })

        # ---------------------------------------------------------------------
        # SKENARIO 3: Kontrol Akses / Broken Access Control (RBAC)
        # ---------------------------------------------------------------------
        # Logout admin, buat sesi sebagai user biasa (petugas gudang)
        client.get('/logout')
        with client.session_transaction() as sess:
            sess['user_id'] = 999
            sess['username'] = 'petugas_testing'
            sess['role'] = 'petugas'
            sess['csrf_token'] = valid_csrf

        # 1. Petugas mencoba akses halaman Audit Log khusus Admin
        res_rbac1 = client.get('/audit_log')
        # 2. Petugas mencoba hapus barang (ID: 1)
        res_rbac2 = client.post('/hapus_barang/1', data={'csrf_token': valid_csrf})
        # 3. Petugas mencoba menambah barang baru (DILARANG: Hanya Admin yang boleh tambah barang)
        res_rbac3 = client.post('/tambah_barang', data={'nama_barang': 'Barang Ilegal Petugas', 'deskripsi': 'Uji RBAC', 'csrf_token': valid_csrf})

        rbac_passed = (res_rbac1.status_code == 403 and res_rbac2.status_code == 403 and res_rbac3.status_code == 403)
        results.append({
            'no': 3,
            'skenario': 'Broken Access Control (Hak Akses Petugas vs Admin)',
            'metode': "Petugas mengakses /audit_log, POST /hapus_barang, & POST /tambah_barang",
            'ekspektasi': 'Semua aksi non-petugas ditolak (HTTP 403 Forbidden)',
            'status': 'LOLOS (SECURE)' if rbac_passed else 'GAGAL'
        })

        # ---------------------------------------------------------------------
        # SKENARIO 4: Validasi Kompleksitas Password (Password Policy)
        # ---------------------------------------------------------------------
        client.get('/logout')
        client.get('/register')
        with client.session_transaction() as sess:
            reg_csrf = sess.get('csrf_token')

        # Coba daftar dengan password lemah (hanya huruf kecil atau kurang dari 8 karakter)
        res_pw_weak = client.post('/register', data={
            'username': 'usertest_lemah',
            'password': 'password123', # Tidak ada simbol & huruf kapital
            'role': 'petugas',
            'csrf_token': reg_csrf
        })

        pw_passed = (res_pw_weak.status_code == 200 and "Password harus mengandung" in res_pw_weak.data.decode('utf-8'))
        results.append({
            'no': 4,
            'skenario': 'Validasi Kompleksitas Password (Password Policy)',
            'metode': "Mencoba registrasi dengan password 'password123' (tanpa simbol & huruf besar)",
            'ekspektasi': 'Registrasi ditolak; muncul instruksi kombinasi karakter wajib',
            'status': 'LOLOS (SECURE)' if pw_passed else 'GAGAL'
        })

        # ---------------------------------------------------------------------
        # SKENARIO 5: Rate Limiting (Pencegahan Brute-Force Login)
        # ---------------------------------------------------------------------
        # Kirim 5 kali password salah berturut-turut
        locked_out = False
        with client.session_transaction() as sess:
            rf_csrf = sess.get('csrf_token')

        for i in range(5):
            res_fail = client.post('/login', data={
                'username': 'bruteforce_target',
                'password': f'wrong_pass_{i}',
                'csrf_token': rf_csrf
            })
            if "diblokir" in res_fail.data.decode('utf-8'):
                locked_out = True

        results.append({
            'no': 5,
            'skenario': 'Pencegahan Brute-Force (Rate Limiting)',
            'metode': 'Memasukkan 5 kali password salah berturut-turut pada username yang sama',
            'ekspektasi': 'Akun/IP diblokir sementara selama 60 detik (Lockout aktif)',
            'status': 'LOLOS (SECURE)' if locked_out else 'GAGAL'
        })

        # ---------------------------------------------------------------------
        # SKENARIO 6: Proteksi CSRF (Cross-Site Request Forgery)
        # ---------------------------------------------------------------------
        # Kirim request berbahaya tanpa menyertakan csrf_token
        res_csrf_bad = client.post('/tambah_barang', data={
            'nama_barang': 'Barang_Ilegal_CSRF',
            'deskripsi': 'Injeksi request luar'
        })
        csrf_passed = (res_csrf_bad.status_code == 403 and "CSRF" in res_csrf_bad.data.decode('utf-8'))
        results.append({
            'no': 6,
            'skenario': 'Proteksi CSRF (Cross-Site Request Forgery)',
            'metode': 'Mengirim request POST /tambah_barang tanpa token CSRF yang valid',
            'ekspektasi': 'Akses Ditolak (HTTP 403 Forbidden; Validasi CSRF Gagal)',
            'status': 'LOLOS (SECURE)' if csrf_passed else 'GAGAL'
        })

        # ---------------------------------------------------------------------
        # SKENARIO 7: HTTP Security Headers
        # ---------------------------------------------------------------------
        res_header = client.get('/login')
        h = res_header.headers
        headers_ok = (
            h.get('X-Frame-Options') == 'SAMEORIGIN' and
            h.get('X-Content-Type-Options') == 'nosniff' and
            h.get('X-XSS-Protection') == '1; mode=block' and
            'Content-Security-Policy' in h and
            'Referrer-Policy' in h
        )
        results.append({
            'no': 7,
            'skenario': 'HTTP Security Headers (OWASP Hardening)',
            'metode': 'Memeriksa header respon HTTP (X-Frame-Options, CSP, nosniff, dsb.)',
            'ekspektasi': 'Semua security header wajib terpasang pada respon server',
            'status': 'LOLOS (SECURE)' if headers_ok else 'GAGAL'
        })

        # ---------------------------------------------------------------------
        # SKENARIO 8: Kelengkapan Operasi CRUD Data
        # ---------------------------------------------------------------------
        with client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['username'] = 'admin'
            sess['role'] = 'admin'
            admin_csrf = sess.get('csrf_token')

        # Create
        res_c = client.post('/tambah_barang', data={'nama_barang': 'Komputer Test', 'deskripsi': 'Lab PC', 'csrf_token': admin_csrf}, follow_redirects=True)
        # Read
        res_r = client.get('/')
        # Update (Edit Barang & Update Stok)
        with app.app_context():
            item = Barang.query.filter_by(nama_barang='Komputer Test').first()
            item_id = item.id if item else 1
        res_u1 = client.post(f'/edit_barang/{item_id}', data={'nama_barang': 'Komputer Test (Rev)', 'deskripsi': 'Lab PC Baru', 'csrf_token': admin_csrf}, follow_redirects=True)
        res_u2 = client.post(f'/update_stok/{item_id}', data={'jenis': 'masuk', 'jumlah': 5, 'csrf_token': admin_csrf}, follow_redirects=True)
        # Delete
        res_d = client.post(f'/hapus_barang/{item_id}', data={'csrf_token': admin_csrf}, follow_redirects=True)

        crud_passed = (res_c.status_code == 200 and res_r.status_code == 200 and res_u1.status_code == 200 and res_u2.status_code == 200 and res_d.status_code == 200)
        results.append({
            'no': 8,
            'skenario': 'Fungsi Pengelolaan Data Lengkap (CRUD)',
            'metode': 'Uji Create, Read, Update (Edit Data & Stok), dan Delete secara berurutan',
            'ekspektasi': 'Semua operasi CRUD berhasil dieksekusi tanpa error',
            'status': 'LOLOS (BERFUNGSI)' if crud_passed else 'GAGAL'
        })

        # ---------------------------------------------------------------------
        # SKENARIO 9: Fitur Restock Petugas Gudang & Ekspor Laporan Resmi PDF
        # ---------------------------------------------------------------------
        # Sesi petugas gudang
        with client.session_transaction() as sess:
            sess['user_id'] = 2
            sess['username'] = 'petugas_gudang'
            sess['role'] = 'petugas'
            petugas_csrf = sess.get('csrf_token')

        # 1. Pastikan minimal ada 1 barang untuk direstock
        with app.app_context():
            barang_sample = Barang.query.first()
            if not barang_sample:
                b_new = Barang(nama_barang="Komoditas Test PDF", deskripsi="Sample", jumlah_stok=10)
                db.session.add(b_new)
                db.session.commit()
                b_id = b_new.id
            else:
                b_id = barang_sample.id

        # 2. Petugas melakukan restock barang masuk
        res_restock = client.post('/restock_barang', data={'id_barang': b_id, 'jumlah': 15, 'csrf_token': petugas_csrf}, follow_redirects=True)
        # 3. Unduh Laporan PDF
        res_pdf = client.get('/laporan_pdf')

        pdf_ok = (
            res_restock.status_code == 200 and
            res_pdf.status_code == 200 and
            res_pdf.mimetype == 'application/pdf' and
            res_pdf.data.startswith(b'%PDF')
        )
        results.append({
            'no': 9,
            'skenario': 'Restock Petugas Gudang & Unduh Laporan PDF',
            'metode': 'POST /restock_barang oleh Petugas dan GET /laporan_pdf',
            'ekspektasi': 'Restock sukses tercatat & PDF valid dihasilkan (mimetype application/pdf)',
            'status': 'LOLOS (BERFUNGSI)' if pdf_ok else 'GAGAL'
        })

    # Cetak Tabel Hasil
    print(f"\n{'No':<3} | {'Skenario Uji':<35} | {'Ekspektasi Keamanan':<45} | {'Hasil':<15}")
    print("-" * 105)
    all_passed = True
    for r in results:
        status_str = r['status']
        if 'GAGAL' in status_str:
            all_passed = False
        print(f"{r['no']:<3} | {r['skenario']:<35} | {r['ekspektasi'][:43]:<45} | {status_str:<15}")

    print("=" * 105)
    if all_passed:
        print("  KESIMPULAN: SEMUA PENGUJIAN KEAMANAN LOLOS (100% PASS - SIAP DINILAI)")
    else:
        print("  KESIMPULAN: TERDAPAT PENGUJIAN YANG GAGAL. SILAKAN CEK DETAIL DI ATAS.")
    print("=" * 105)

    return all_passed

if __name__ == '__main__':
    run_tests()
