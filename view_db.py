r"""
Script praktis untuk melihat seluruh isi database SQLite (inventory.db)
Jalankan dengan: python view_db.py atau .\env\Scripts\python.exe view_db.py
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'inventory.db')

def view_database():
    if not os.path.exists(DB_PATH):
        print(f"[ERROR] Database tidak ditemukan di: {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Ambil semua tabel
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
    tables = [row[0] for row in cursor.fetchall()]

    print("=" * 80)
    print(f"  ISI DATABASE: {DB_PATH}")
    print("=" * 80)

    for table in tables:
        print(f"\n📦 TABEL: [{table.upper()}]")
        print("-" * 80)
        
        # Ambil nama kolom
        cursor.execute(f"PRAGMA table_info({table});")
        columns = [col[1] for col in cursor.fetchall()]
        
        # Ambil data
        cursor.execute(f"SELECT * FROM {table};")
        rows = cursor.fetchall()

        if not rows:
            print("  (Tabel masih kosong)")
            continue

        # Format header
        header = " | ".join(f"{col:<18}" for col in columns)
        print(header)
        print("-" * len(header))

        # Format baris
        for row in rows:
            row_str = " | ".join(f"{str(val)[:18]:<18}" for val in row)
            print(row_str)

        print(f"Total: {len(rows)} baris data.")

    conn.close()
    print("\n" + "=" * 80)

if __name__ == '__main__':
    view_database()
