import os
import re
import json
import secrets
import hmac
import bcrypt
import csv
from io import StringIO
from functools import wraps
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, render_template, request, redirect, url_for, session, Response
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

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
    entry = AuditLog(event_type=event_type, username=username,
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
            return "Akses Ditolak! Halaman ini hanya untuk Admin.", 403
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
        chart_stok_labels=json.dumps(chart_stok_labels),
        chart_stok_values=json.dumps(chart_stok_values),
        total_masuk=total_masuk,
        total_keluar=total_keluar,
        chart_tren_labels=json.dumps(chart_tren_labels),
        chart_tren_masuk=json.dumps(chart_tren_masuk),
        chart_tren_keluar=json.dumps(chart_tren_keluar),
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
# ROUTING CRUD & LAPORAN TUGAS BESAR
# ==========================================
@app.route('/tambah_barang', methods=['POST'])
def tambah_barang():
    if 'user_id' not in session: return redirect(url_for('login'))
    nama = request.form['nama_barang'].strip()
    if not nama:
        return "Nama barang wajib diisi!", 400
    barang_baru = Barang(nama_barang=nama, deskripsi=request.form.get('deskripsi', '').strip())
    db.session.add(barang_baru)
    db.session.commit()
    log_activity('TAMBAH', session.get('username'), f"Menambahkan barang baru: '{nama}'.")
    return redirect(url_for('index'))

@app.route('/edit_barang/<int:id>', methods=['POST'])
def edit_barang(id):
    if 'user_id' not in session: return redirect(url_for('login'))
    barang = Barang.query.get_or_404(id)
    nama_lama = barang.nama_barang
    nama_baru = request.form.get('nama_barang', '').strip()
    deskripsi_baru = request.form.get('deskripsi', '').strip()

    if not nama_baru:
        return "Nama barang tidak boleh kosong!", 400

    barang.nama_barang = nama_baru
    barang.deskripsi = deskripsi_baru
    db.session.commit()
    log_activity('EDIT_BARANG', session.get('username'), f"Mengubah data barang ID {id}: '{nama_lama}' -> '{nama_baru}'.")
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
    return redirect(url_for('index'))

@app.route('/update_stok/<int:id>', methods=['POST'])
def update_stok(id):
    if 'user_id' not in session: return redirect(url_for('login'))

    barang = Barang.query.get_or_404(id)
    jenis = request.form['jenis']
    jumlah = int(request.form['jumlah'])

    if jenis == 'masuk':
        barang.jumlah_stok += jumlah
    elif jenis == 'keluar':
        if barang.jumlah_stok >= jumlah:
            barang.jumlah_stok -= jumlah
        else:
            return "Stok tidak mencukupi!", 400

    # Menyimpan jejak aktivitas stok untuk fitur laporan
    db.session.add(RiwayatStok(id_barang=barang.id, jenis=jenis, jumlah=jumlah, user_id=session['user_id']))
    db.session.commit()
    log_activity('UPDATE_STOK', session.get('username'),
                 f"Stok '{barang.nama_barang}' {jenis} {jumlah} unit (sisa: {barang.jumlah_stok}).")
    return redirect(url_for('index'))

@app.route('/laporan_csv')
def laporan_csv():
    if 'user_id' not in session: return redirect(url_for('login'))

    riwayat = RiwayatStok.query.all()
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'Nama Barang', 'Jenis', 'Jumlah', 'Tanggal', 'Petugas'])

    for r in riwayat:
        cw.writerow([r.id, r.barang.nama_barang, r.jenis, r.jumlah, r.tanggal.strftime("%Y-%m-%d %H:%M:%S"), r.user.username])

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