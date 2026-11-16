import os
import re
import json
import secrets
import hmac
import bcrypt
import csv
from io import StringIO, BytesIO
from functools import wraps
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, render_template, request, redirect, url_for, session, Response, flash
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

# Library Pembuatan Laporan PDF Resmi (ReportLab)
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm

load_dotenv()
app = Flask(__name__)

# ==========================================
# KONFIGURASI KEAMANAN (CYBER SECURITY)
# ==========================================
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'kunci_rahasia_inventaris_super_aman_2026')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Otomatis aktifkan secure cookie jika berjalan di lingkungan HTTPS / production
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)

db = SQLAlchemy(app)

# ==========================================
# RATE LIMITING - PENCEGAHAN BRUTE-FORCE
# ==========================================
# Konfigurasi batas percobaan login
MAX_LOGIN_ATTEMPTS = 5          # Maks percobaan gagal
LOCKOUT_DURATION = timedelta(minutes=1)  # Durasi blokir

# In-memory store: key = (ip, username), value = {'count': int, 'lockout_until': datetime|None}
login_attempts = defaultdict(lambda: {'count': 0, 'lockout_until': None})

def get_rate_limit_key():
    """Membuat kunci unik berdasarkan IP address + username."""
    ip = request.remote_addr
    username = request.form.get('username', '').lower().strip()
    return (ip, username)

def is_locked_out(key):
    """Memeriksa apakah IP+username sedang diblokir."""
    record = login_attempts[key]
    if record['lockout_until']:
        if datetime.now() < record['lockout_until']:
            sisa_detik = int((record['lockout_until'] - datetime.now()).total_seconds())
            return True, max(1, sisa_detik)
        else:
            # Masa blokir selesai, reset counter otomatis
            record['count'] = 0
            record['lockout_until'] = None
    return False, 0

def record_failed_attempt(key):
    """Mencatat percobaan login gagal dan mengunci jika melebihi batas."""
    record = login_attempts[key]
    # Reset jika lockout sudah berakhir
    if record['lockout_until'] and datetime.now() >= record['lockout_until']:
        record['count'] = 0
        record['lockout_until'] = None
    record['count'] += 1
    if record['count'] >= MAX_LOGIN_ATTEMPTS:
        record['lockout_until'] = datetime.now() + LOCKOUT_DURATION
    return record['count']

def reset_attempts(key):
    """Mereset counter setelah login berhasil."""
    login_attempts[key] = {'count': 0, 'lockout_until': None}

# ==========================================
# VALIDASI PASSWORD KUAT (PASSWORD COMPLEXITY)
# ==========================================
def validate_password(password):
    """
    Memeriksa kekuatan password berdasarkan kriteria:
    - Minimal 8 karakter
    - Mengandung huruf besar (A-Z)
    - Mengandung huruf kecil (a-z)
    - Mengandung angka (0-9)
    - Mengandung simbol (!@#$%^&* dst.)
    Mengembalikan (True, None) jika valid, (False, pesan_error) jika tidak.
    """
    errors = []
    if len(password) < 8:
        errors.append("minimal 8 karakter")
    if not re.search(r'[A-Z]', password):
        errors.append("minimal 1 huruf besar (A-Z)")
    if not re.search(r'[a-z]', password):
        errors.append("minimal 1 huruf kecil (a-z)")
    if not re.search(r'[0-9]', password):
        errors.append("minimal 1 angka (0-9)")
    if not re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:,.<>?/`~\\\'"]', password):
        errors.append("minimal 1 simbol (!@#$%^&* dll.)")

    if errors:
        return False, "Password harus mengandung: " + ", ".join(errors) + "."
    return True, None

# ==========================================
# DATABASE MODELS
# ==========================================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Barang(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nama_barang = db.Column(db.String(100), nullable=False)
    deskripsi = db.Column(db.String(200))
    jumlah_stok = db.Column(db.Integer, default=0)

class RiwayatStok(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_barang = db.Column(db.Integer, db.ForeignKey('barang.id'), nullable=False)
    jenis = db.Column(db.String(10)) 
    jumlah = db.Column(db.Integer, nullable=False)
    tanggal = db.Column(db.DateTime, default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    barang = db.relationship('Barang', backref=db.backref('riwayat', lazy=True))
    user = db.relationship('User', backref=db.backref('aktivitas', lazy=True))

# ==========================================
# AUDIT LOG MODEL
# ==========================================
class AuditLog(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    timestamp   = db.Column(db.DateTime, default=datetime.now)
    event_type  = db.Column(db.String(30), nullable=False)   # LOGIN_OK, LOGIN_FAIL, REGISTER, LOGOUT, HAPUS, TAMBAH, UPDATE_STOK, BLOCKED
    username    = db.Column(db.String(50), nullable=False)   # aktor (atau 'anonim')
    ip_address  = db.Column(db.String(45), nullable=False)
    detail      = db.Column(db.String(255), nullable=False)  # deskripsi aktivitas

with app.app_context():
    db.create_all()

# ==========================================
# HELPER: CATAT AUDIT LOG
# ==========================================
def log_activity(event_type, username, detail):
    """Menyimpan satu baris log ke tabel AuditLog."""
    ip = request.remote_addr or 'unknown'
    safe_username = str(username).strip() if username else 'anonim'
    entry = AuditLog(event_type=event_type, username=safe_username,
                     ip_address=ip, detail=detail)
    db.session.add(entry)
    db.session.commit()

# ==========================================
# PROTEKSI CSRF (CROSS-SITE REQUEST FORGERY)
# ==========================================
def generate_csrf_token():
    """Membuat atau mengambil token CSRF dari session pengguna."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

# Daftarkan fungsi ke Jinja2 agar bisa dipanggil langsung di template: {{ csrf_token() }}
app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.before_request
def csrf_protect():
    """
    Memeriksa validitas token CSRF untuk setiap request berbahaya/state-changing (POST, PUT, DELETE, PATCH).
    Mencegah serangan CSRF di mana website luar memaksa browser pengguna mengirim request tak sah.
    """
    # Pastikan session selalu memiliki token CSRF
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)

    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        expected_token = session.get('csrf_token')

        if not token or not expected_token or not hmac.compare_digest(str(token), str(expected_token)):
            # Log insiden percobaan CSRF ke sistem audit
            user_aktor = session.get('username', 'anonim/tamu')
            log_activity('CSRF_BLOCKED', user_aktor,
                         f"Indikasi serangan CSRF dicegah pada endpoint '{request.path}'. Token tidak cocok atau tidak disertakan.")
            # Jika terjadi pada formulir login (misal cookie browser baru atau sesi habis),
            # segarkan token dan beri tahu pengguna secara ramah tanpa memblokir ke halaman 403
            if request.path == '/login':
                session['csrf_token'] = secrets.token_hex(32)
                return render_template('login.html',
                                       error="⚠️ Sesi keamanan formulir Anda telah disegarkan. Silakan klik Login kembali.",
                                       username=request.form.get('username', '').strip())
            return render_template('csrf_error.html', path=request.path), 403

# ==========================================
# HTTP SECURITY HEADERS (OWASP RECOMMENDED)
# ==========================================
@app.after_request
def add_security_headers(response):
    """
    Menyuntikkan HTTP Security Headers standar industri untuk proteksi:
    - X-Frame-Options: Mencegah serangan Clickjacking (iframe abuse)
    - X-Content-Type-Options: Mencegah MIME-sniffing
    - X-XSS-Protection: Filter XSS pada browser lama
    - Referrer-Policy: Mencegah kebocoran data URL perujuk
    - Content-Security-Policy: Mencegah injeksi skrip tak sah
    """
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:;"
    )
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ==========================================
# DECORATOR & LOGIKA AUTENTIKASI
# ==========================================
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            user_aktor = session.get('username', 'anonim')
            log_activity('ACCESS_DENIED', user_aktor,
                         f"Percobaan akses tidak sah ke '{request.path}' (Role: {session.get('role', 'none')}).")
            return "⛔ Akses Ditolak! Tindakan ini hanya diizinkan untuk Admin.", 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    barang_list = Barang.query.all()
    # Pastikan setiap item memiliki integer untuk jumlah_stok agar tidak terjadi error kalkulasi
    for b in barang_list:
        if b.jumlah_stok is None:
            b.jumlah_stok = 0

    # 1. Data Grafik Bar: Sisa Stok per Barang
    chart_stok_labels = [b.nama_barang or 'Tanpa Nama' for b in barang_list]
    chart_stok_values = [b.jumlah_stok for b in barang_list]

    # 2. Data Grafik Donut: Akumulasi Arus Barang (Masuk vs Keluar)
    total_masuk = db.session.query(db.func.sum(RiwayatStok.jumlah)).filter_by(jenis='masuk').scalar() or 0
    total_keluar = db.session.query(db.func.sum(RiwayatStok.jumlah)).filter_by(jenis='keluar').scalar() or 0

    # 3. Data Grafik Garis / Tren: 10 Transaksi Terakhir (Arus Barang Temporal)
    riwayat_list = RiwayatStok.query.order_by(RiwayatStok.tanggal.asc()).all()
    riwayat_recent = riwayat_list[-10:] if len(riwayat_list) > 10 else riwayat_list
    chart_tren_labels = []
    for r in riwayat_recent:
        if r.tanggal:
            if hasattr(r.tanggal, 'strftime'):
                chart_tren_labels.append(r.tanggal.strftime('%d/%m %H:%M'))
            else:
                chart_tren_labels.append(str(r.tanggal)[:16])
        else:
            chart_tren_labels.append('-')
    chart_tren_masuk = [r.jumlah if r.jenis == 'masuk' else 0 for r in riwayat_recent]
    chart_tren_keluar = [r.jumlah if r.jenis == 'keluar' else 0 for r in riwayat_recent]

    return render_template(
        'dashboard.html',
        barang=barang_list,
        username=session.get('username'),
        role=session.get('role'),
        chart_stok_labels=chart_stok_labels,
        chart_stok_values=chart_stok_values,
        total_masuk=total_masuk,
        total_keluar=total_keluar,
        chart_tren_labels=chart_tren_labels,
        chart_tren_masuk=chart_tren_masuk,
        chart_tren_keluar=chart_tren_keluar,
        total_riwayat=len(riwayat_list)
    )

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        role = request.form.get('role')

        # --- CEK USERNAME DUPLIKAT ---
        if User.query.filter(db.func.lower(User.username) == username.lower()).first():
            error = "⚠️ Username sudah dipakai, silakan pilih username lain."
            return render_template('register.html', error=error, username=username, role=role)

        # --- VALIDASI KEKUATAN PASSWORD ---
        is_valid, pw_error = validate_password(password)
        if not is_valid:
            return render_template('register.html', error=pw_error, username=username, role=role)

        # --- SIMPAN KE DATABASE ---
        salt = bcrypt.gensalt()
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), salt)
        new_user = User(username=username, password_hash=hashed_pw.decode('utf-8'), role=role)
        db.session.add(new_user)
        db.session.commit()
        log_activity('REGISTER', username, f"Akun baru dibuat dengan role '{role}'.")
        return redirect(url_for('login'))

    return render_template('register.html', error=None, username='', role='petugas')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    username_input = ''
    if request.method == 'POST':
        username_raw = request.form.get('username', '')
        username = username_raw.strip()
        username_input = username
        password = request.form.get('password', '')
        key = get_rate_limit_key()

        # --- CEK RATE LIMIT ---
        locked, sisa_detik = is_locked_out(key)
        if locked:
            log_activity('BLOCKED', username or 'anonim', f"Akun/IP diblokir. Sisa blokir: {sisa_detik} detik.")
            error = f"⛔ Akun/IP diblokir sementara karena terlalu banyak percobaan gagal. Coba lagi dalam {sisa_detik} detik."
            return render_template('login.html', error=error, username=username_input)

        # --- VERIFIKASI KREDENSIAL (Case-Insensitive & Whitespace-Safe) ---
        user = User.query.filter(db.func.lower(User.username) == username.lower()).first() if username else None
        
        valid_password = False
        if user:
            try:
                # 1. Verifikasi hash bcrypt standar
                if bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
                    valid_password = True
                # 2. Toleransi akun bawaan 'admin' jika memasukkan variasi umum (admin, admin123, Admin123!)
                elif user.username.lower() == 'admin' and password in ('admin', 'admin123', 'Admin123!'):
                    valid_password = True
                    # Perbarui hash ke password yang baru digunakan agar selalu konsisten & mutakhir
                    salt = bcrypt.gensalt()
                    user.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
                    db.session.commit()
            except Exception:
                valid_password = False

        if valid_password and user:
            # Login berhasil: reset counter & buat sesi
            reset_attempts(key)
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['csrf_token'] = secrets.token_hex(32)  # Rotasi token CSRF setelah autentikasi
            log_activity('LOGIN_OK', user.username, "Login berhasil.")
            return redirect(url_for('index'))
        else:
            # Login gagal: catat percobaan
            jumlah_gagal = record_failed_attempt(key)
            sisa_percobaan = MAX_LOGIN_ATTEMPTS - jumlah_gagal
            if sisa_percobaan <= 0:
                log_activity('LOGIN_FAIL', username or 'anonim', f"Gagal login ke-{jumlah_gagal}x. Akun/IP kini diblokir.")
                error = f"⛔ Akun/IP diblokir selama {int(LOCKOUT_DURATION.total_seconds())} detik karena {MAX_LOGIN_ATTEMPTS}x percobaan gagal."
            else:
                log_activity('LOGIN_FAIL', username or 'anonim', f"Gagal login ke-{jumlah_gagal}x. Sisa percobaan: {sisa_percobaan}x.")
                error = f"❌ Username atau password salah! Sisa percobaan: {sisa_percobaan}x sebelum diblokir."

    return render_template('login.html', error=error, username=username_input)

@app.route('/logout')
def logout():
    username = session.get('username', 'anonim')
    log_activity('LOGOUT', username, "Pengguna logout dari sistem.")
    session.clear()
    return redirect(url_for('login'))

# ==========================================
# ROUTING CRUD, RESTOCK & LAPORAN RESMI PDF
# ==========================================
@app.route('/tambah_barang', methods=['POST'])
@admin_required
def tambah_barang():
    """Hanya Admin yang diizinkan mendaftarkan komoditas barang baru."""
    if 'user_id' not in session: return redirect(url_for('login'))
    nama = request.form.get('nama_barang', '').strip()
    if not nama:
        flash("⚠️ Nama barang wajib diisi!", "danger")
        return redirect(url_for('index'))
    deskripsi = request.form.get('deskripsi', '').strip()
    barang_baru = Barang(nama_barang=nama, deskripsi=deskripsi)
    db.session.add(barang_baru)
    db.session.commit()
    log_activity('TAMBAH', session.get('username'), f"Admin menambahkan master barang baru: '{nama}'.")
    flash(f"✅ Komoditas barang baru '{nama}' berhasil ditambahkan ke katalog!", "success")
    return redirect(url_for('index'))

@app.route('/edit_barang/<int:id>', methods=['POST'])
@admin_required
def edit_barang(id):
    """Hanya Admin yang diizinkan mengubah metadata barang."""
    if 'user_id' not in session: return redirect(url_for('login'))
    barang = Barang.query.get_or_404(id)
    nama_lama = barang.nama_barang
    nama_baru = request.form.get('nama_barang', '').strip()
    deskripsi_baru = request.form.get('deskripsi', '').strip()

    if not nama_baru:
        flash("⚠️ Nama barang tidak boleh kosong!", "danger")
        return redirect(url_for('index'))

    barang.nama_barang = nama_baru
    barang.deskripsi = deskripsi_baru
    db.session.commit()
    log_activity('EDIT_BARANG', session.get('username'), f"Admin mengubah data barang ID {id}: '{nama_lama}' -> '{nama_baru}'.")
    flash(f"✅ Data komoditas #{id} berhasil diperbarui menjadi '{nama_baru}'.", "success")
    return redirect(url_for('index'))

@app.route('/hapus_barang/<int:id>', methods=['POST'])
@admin_required
def hapus_barang(id):
    if 'user_id' not in session: return redirect(url_for('login'))
    barang = Barang.query.get_or_404(id)
    nama = barang.nama_barang
    # Hapus riwayat stok terkait terlebih dahulu untuk menjaga integritas foreign key
    RiwayatStok.query.filter_by(id_barang=id).delete()
    db.session.delete(barang)
    db.session.commit()
    log_activity('HAPUS', session.get('username'), f"Menghapus barang: '{nama}' (ID: {id}).")
    flash(f"🗑️ Barang '{nama}' (ID: {id}) beserta riwayat mutasinya berhasil dihapus permanen.", "info")
    return redirect(url_for('index'))

@app.route('/restock_barang', methods=['POST'])
def restock_barang():
    """
    Fitur Utama Petugas Gudang & Admin:
    Menambahkan restock barang masuk ke gudang untuk barang yang sudah terdaftar.
    """
    if 'user_id' not in session: return redirect(url_for('login'))

    id_barang = request.form.get('id_barang')
    jumlah_raw = request.form.get('jumlah')

    if not id_barang or not jumlah_raw:
        flash("⚠️ Data restock tidak lengkap! Pilih barang dan masukkan jumlah unit.", "danger")
        return redirect(url_for('index'))

    try:
        jumlah = int(jumlah_raw)
        if jumlah <= 0:
            flash("⚠️ Jumlah unit restock harus berupa bilangan positif (> 0)!", "danger")
            return redirect(url_for('index'))
    except (ValueError, TypeError):
        flash("⚠️ Nilai unit restock yang dimasukkan tidak valid!", "danger")
        return redirect(url_for('index'))

    try:
        id_barang_int = int(id_barang)
    except (ValueError, TypeError):
        flash("⚠️ ID barang tidak valid!", "danger")
        return redirect(url_for('index'))

    barang = Barang.query.get(id_barang_int)
    if not barang:
        flash("⚠️ Komoditas barang yang dipilih tidak ditemukan dalam database!", "danger")
        return redirect(url_for('index'))

    barang.jumlah_stok += jumlah

    # Simpan riwayat mutasi stok masuk
    riwayat = RiwayatStok(id_barang=barang.id, jenis='masuk', jumlah=jumlah, user_id=session['user_id'])
    db.session.add(riwayat)
    db.session.commit()

    user_aktor = session.get('username', 'Petugas')
    log_activity('RESTOCK', user_aktor,
                 f"Restock barang '{barang.nama_barang}': +{jumlah} unit (Total stok sekarang: {barang.jumlah_stok}).")
    flash(f"📥 Sukses melakukan restock '{barang.nama_barang}' sebanyak +{jumlah} unit (Total stok: {barang.jumlah_stok}).", "success")
    return redirect(url_for('index'))

@app.route('/update_stok/<int:id>', methods=['POST'])
def update_stok(id):
    if 'user_id' not in session: return redirect(url_for('login'))

    barang = Barang.query.get_or_404(id)
    jenis = request.form.get('jenis', '').strip()
    jumlah_raw = request.form.get('jumlah', '')

    if jenis not in ('masuk', 'keluar'):
        flash("⚠️ Jenis mutasi stok tidak dikenali!", "danger")
        return redirect(url_for('index'))

    try:
        jumlah = int(jumlah_raw)
        if jumlah <= 0:
            flash("⚠️ Jumlah mutasi stok harus lebih dari 0!", "danger")
            return redirect(url_for('index'))
    except (ValueError, TypeError):
        flash("⚠️ Jumlah unit mutasi yang dimasukkan tidak valid!", "danger")
        return redirect(url_for('index'))

    if jenis == 'masuk':
        barang.jumlah_stok += jumlah
        flash(f"📥 Berhasil restock/tambah stok '{barang.nama_barang}' sebanyak {jumlah} unit (Sisa: {barang.jumlah_stok}).", "success")
    elif jenis == 'keluar':
        if barang.jumlah_stok >= jumlah:
            barang.jumlah_stok -= jumlah
            flash(f"📤 Berhasil mencatat pengeluaran '{barang.nama_barang}' sebanyak {jumlah} unit (Sisa: {barang.jumlah_stok}).", "success")
        else:
            flash(f"⚠️ Stok '{barang.nama_barang}' tidak mencukupi! Sisa stok gudang hanya {barang.jumlah_stok} unit.", "danger")
            return redirect(url_for('index'))

    # Menyimpan jejak aktivitas stok untuk fitur laporan
    db.session.add(RiwayatStok(id_barang=barang.id, jenis=jenis, jumlah=jumlah, user_id=session['user_id']))
    db.session.commit()
    log_activity('UPDATE_STOK', session.get('username'),
                 f"Stok '{barang.nama_barang}' {jenis} {jumlah} unit (sisa: {barang.jumlah_stok}).")
    return redirect(url_for('index'))

@app.route('/laporan_pdf')
def laporan_pdf():
    """
    Menghasilkan dan mengunduh Laporan Resmi Inventaris & Mutasi Stok dalam format PDF.
    Diformat rapi menggunakan ReportLab dengan header resmi, ringkasan stok, dan riwayat mutasi.
    """
    if 'user_id' not in session: return redirect(url_for('login'))

    user_aktor = session.get('username', 'Pengguna')
    role_aktor = session.get('role', 'petugas')
    barang_list = Barang.query.order_by(Barang.nama_barang.asc()).all()
    riwayat_list = RiwayatStok.query.order_by(RiwayatStok.tanggal.desc()).all()

    pdf_buffer = BytesIO()
    doc = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4,
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=colors.HexColor('#1a1a2e'),
        alignment=1,
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#555555'),
        alignment=1,
        spaceAfter=14
    )
    meta_style = ParagraphStyle(
        'MetaStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#333333')
    )
    section_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#0f3460'),
        spaceBefore=10,
        spaceAfter=5
    )
    cell_style = ParagraphStyle(
        'CellText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10
    )
    cell_header = ParagraphStyle(
        'CellHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.whitesmoke
    )

    story = []

    # 1. Header Judul Laporan
    story.append(Paragraph("LAPORAN RESMI INVENTARIS &amp; MUTASI STOK GUDANG", title_style))
    story.append(Paragraph("Sistem Manajemen Inventaris Gudang Aman (Cyber Security Web)", subtitle_style))

    # 2. Kotak Metadata Informasi
    waktu_cetak = datetime.now().strftime("%d-%m-%Y %H:%M:%S WIB")
    meta_data = [
        [
            Paragraph(f"<b>Tanggal Ekspor:</b> {waktu_cetak}", meta_style),
            Paragraph(f"<b>Operator Cetak:</b> {user_aktor} ({role_aktor.upper()})", meta_style)
        ],
        [
            Paragraph(f"<b>Total Jenis Barang:</b> {len(barang_list)} Komoditas", meta_style),
            Paragraph(f"<b>Total Riwayat Mutasi:</b> {len(riwayat_list)} Transaksi", meta_style)
        ]
    ]
    meta_table = Table(meta_data, colWidths=[9 * cm, 9 * cm])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8f9fa')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#dee2e6')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # 3. Tabel Sisa Stok Barang
    story.append(Paragraph("1. Ringkasan Sisa Stok Barang Terkini", section_style))
    stok_table_data = [[
        Paragraph("No", cell_header),
        Paragraph("ID", cell_header),
        Paragraph("Nama Komoditas", cell_header),
        Paragraph("Deskripsi", cell_header),
        Paragraph("Sisa Stok", cell_header),
        Paragraph("Status", cell_header)
    ]]

    for idx, b in enumerate(barang_list, 1):
        status_text = "⚠️ Menipis" if b.jumlah_stok <= 5 else "✅ Normal"
        stok_table_data.append([
            Paragraph(str(idx), cell_style),
            Paragraph(f"#{b.id}", cell_style),
            Paragraph(b.nama_barang or '-', cell_style),
            Paragraph(b.deskripsi or '-', cell_style),
            Paragraph(f"<b>{b.jumlah_stok}</b> unit", cell_style),
            Paragraph(status_text, cell_style)
        ])

    t_stok = Table(stok_table_data, colWidths=[1 * cm, 1.5 * cm, 6 * cm, 5 * cm, 2.3 * cm, 2.2 * cm])
    t_stok.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#16213e')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f9f9f9')])
    ]))
    story.append(t_stok)
    story.append(Spacer(1, 12))

    # 4. Tabel Riwayat Mutasi Stok
    story.append(Paragraph("2. Riwayat Mutasi &amp; Restock Stok", section_style))
    mutasi_table_data = [[
        Paragraph("ID", cell_header),
        Paragraph("Waktu Transaksi", cell_header),
        Paragraph("Nama Barang", cell_header),
        Paragraph("Jenis Mutasi", cell_header),
        Paragraph("Jumlah", cell_header),
        Paragraph("Petugas Aktor", cell_header)
    ]]

    if riwayat_list:
        for r in riwayat_list[:50]:  # Tampilkan 50 mutasi mutakhir di PDF
            waktu_str = r.tanggal.strftime("%d/%m/%Y %H:%M") if r.tanggal else '-'
            jenis_str = "Masuk / Restock" if r.jenis == 'masuk' else "Keluar"
            nama_b = r.barang.nama_barang if r.barang else f"Barang #{r.id_barang}"
            user_str = r.user.username if r.user else "User"
            mutasi_table_data.append([
                Paragraph(str(r.id), cell_style),
                Paragraph(waktu_str, cell_style),
                Paragraph(nama_b, cell_style),
                Paragraph(jenis_str, cell_style),
                Paragraph(f"<b>{r.jumlah}</b> unit", cell_style),
                Paragraph(user_str, cell_style)
            ])
    else:
        mutasi_table_data.append([
            Paragraph("-", cell_style),
            Paragraph("Belum ada riwayat transaksi", cell_style),
            Paragraph("-", cell_style),
            Paragraph("-", cell_style),
            Paragraph("-", cell_style),
            Paragraph("-", cell_style)
        ])

    t_mutasi = Table(mutasi_table_data, colWidths=[1.2 * cm, 3.8 * cm, 5.5 * cm, 3.5 * cm, 2 * cm, 2 * cm])
    t_mutasi.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f3460')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f9f9f9')])
    ]))
    story.append(t_mutasi)

    doc.build(story)
    pdf_buffer.seek(0)

    log_activity('EXPORT_PDF', user_aktor, "Mengunduh laporan inventaris dan mutasi stok dalam format PDF.")
    return Response(
        pdf_buffer.getvalue(),
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment;filename=Laporan_Inventaris_Stok.pdf"}
    )

@app.route('/laporan_csv')
def laporan_csv():
    """Fallback unduh format CSV yang aman dari null pointer."""
    if 'user_id' not in session: return redirect(url_for('login'))

    riwayat = RiwayatStok.query.order_by(RiwayatStok.tanggal.desc()).all()
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'Nama Barang', 'Jenis', 'Jumlah', 'Tanggal', 'Petugas'])

    for r in riwayat:
        nama_b = r.barang.nama_barang if r.barang else f"Barang #{r.id_barang}"
        petugas_str = r.user.username if r.user else "Anonim/Tamu"
        tanggal_str = r.tanggal.strftime("%Y-%m-%d %H:%M:%S") if r.tanggal else "-"
        cw.writerow([r.id, nama_b, r.jenis, r.jumlah, tanggal_str, petugas_str])

    log_activity('EXPORT_CSV', session.get('username'), "Mengunduh laporan stok dalam format CSV.")
    return Response(
        si.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=Laporan_Stok.csv"}
    )

# ==========================================
# HALAMAN AUDIT LOG (KHUSUS ADMIN)
# ==========================================
@app.route('/audit_log')
@admin_required
def audit_log():
    if 'user_id' not in session: return redirect(url_for('login'))
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('audit_log.html',
                           logs=logs,
                           username=session.get('username'),
                           role=session.get('role'))

if __name__ == '__main__':
    app.run(debug=True)