from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
import sqlite3
from datetime import datetime
import os
import base64
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'dein_geheimer_schluessel'  # Bitte in der Produktion durch einen sicheren Schlüssel ersetzen

DB_PATH = "devices.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Damit Zeilen als dict-artige Objekte zurückkommen
    return conn

def init_db():
    """Erstellt die Tabellen devices und users, falls diese noch nicht existieren.
    Fügt einen Default-Admin hinzu (Benutzer: admin, Passwort: admin)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # Tabelle für Geräte
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        inventory_number TEXT UNIQUE NOT NULL,
        user TEXT,
        checked_out_at TEXT,
        checked_in_at TEXT,
        signature TEXT
    )
    """)
    # Tabelle für Benutzer
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )
    """)
    # Prüfen, ob Admin bereits existiert; falls nicht, Default-Admin anlegen
    cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    if cursor.fetchone() is None:
        admin_password = generate_password_hash("admin")  # Default-Passwort; in der Produktion ändern!
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                       ("admin", admin_password, "admin"))
    conn.commit()
    conn.close()

# Login-Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Bitte anmelden!")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin-Decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('role') != 'admin':
            flash("Admin Rechte benötigt!")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Startseite: Je nach Session wird entweder zum Login oder zu einem der Bereiche weitergeleitet
@app.route('/')
def index():
    if 'username' in session:
        if session.get('role') == "admin":
            return redirect(url_for('admin_area'))
        else:
            return redirect(url_for('user_area'))
    return redirect(url_for('login'))

# Login-Routen
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['role'] = user['role']
            flash("Erfolgreich angemeldet!")
            if user['role'] == "admin":
                return redirect(url_for('admin_area'))
            else:
                return redirect(url_for('user_area'))
        else:
            flash("Ungültige Anmeldedaten")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Abgemeldet!")
    return redirect(url_for('login'))

# Benutzer-Dashboard: Hier wird die Liste aller registrierten Nutzer (als mögliche Borrower) geladen
@app.route('/dashboard')
@login_required
def user_area():
    conn = get_db_connection()
    cursor = conn.execute("SELECT username FROM users")
    borrowers = [row['username'] for row in cursor.fetchall()]
    conn.close()
    return render_template('dashboard.html', borrowers=borrowers)

# Admin-Dashboard: Übersicht aller Geräte
@app.route('/admin')
@admin_required
def admin_area():
    conn = get_db_connection()
    cursor = conn.execute("SELECT * FROM devices")
    devices = cursor.fetchall()
    conn.close()
    return render_template('admin.html', devices=devices)

# API-Endpunkt: Gerät ausleihen (Check-out)
@app.route('/check_out', methods=['POST'])
@login_required
def check_out():
    data = request.json
    inventory_number = data.get('inventory_number')
    borrower = data.get('borrower')
    signature = data.get('signature')
    
    # Überprüfen, ob alle nötigen Daten vorhanden sind
    if not inventory_number or not borrower or not signature or signature.strip() == "":
        return jsonify({"error": "Inventarnummer, Borrower und Unterschrift sind erforderlich."}), 400
    
    now = datetime.utcnow().isoformat()
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Falls das Gerät noch nicht in der Datenbank ist, wird ein neuer Eintrag erstellt.
        cursor.execute("""
           INSERT INTO devices (inventory_number, user, checked_out_at, signature)
           VALUES (?, ?, ?, ?)
        """, (inventory_number, borrower, now, signature))
    except sqlite3.IntegrityError:
        # Existierender Eintrag: Update der Check-out-Informationen
        cursor.execute("""
           UPDATE devices
           SET user = ?, checked_out_at = ?, checked_in_at = NULL, signature = ?
           WHERE inventory_number = ?
        """, (borrower, now, signature, inventory_number))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Device {inventory_number} wurde von {borrower} mit Unterschrift ausgeliehen."}), 200

# API-Endpunkt: Gerät zurückgeben (Check-in)
@app.route('/check_in', methods=['POST'])
@login_required
def check_in():
    data = request.json
    inventory_number = data.get('inventory_number')
    
    if not inventory_number:
        return jsonify({"error": "Inventarnummer is required"}), 400
    
    now = datetime.utcnow().isoformat()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE devices SET user = NULL, checked_in_at = ? WHERE inventory_number = ?
    """, (now, inventory_number))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Device {inventory_number} wurde zurückgegeben."}), 200

# Unterschriften-Speicherung (falls getrennt benötigt – alternativ auch über check_out integriert)
@app.route('/save_signature', methods=["POST"])
@login_required
def save_signature():
    data = request.json
    signature_data = data.get("signature")
    inventory_number = data.get("inventory_number")
    if not signature_data or not inventory_number:
        return jsonify({"error": "Signature and inventory number are required"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE devices SET signature = ? WHERE inventory_number = ?
    """, (signature_data, inventory_number))
    conn.commit()
    conn.close()
    return jsonify({"message": "Unterschrift gespeichert"}), 200

# Admin: Bearbeiten von Geräte-Einträgen (z.B. falls etwas korrigiert werden muss)
@app.route('/edit_device', methods=["POST"])
@admin_required
def edit_device():
    data = request.json
    device_id = data.get("id")
    inventory_number = data.get("inventory_number")
    user_assigned = data.get("user")
    checked_out_at = data.get("checked_out_at")
    checked_in_at = data.get("checked_in_at")
    
    if not device_id:
        return jsonify({"error": "Device ID is required"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE devices
        SET inventory_number = ?, user = ?, checked_out_at = ?, checked_in_at = ?
        WHERE id = ?
    """, (inventory_number, user_assigned, checked_out_at, checked_in_at, device_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Device updated successfully"}), 200

# --- Admin-Funktionen für die Nutzerverwaltung ---

# Übersicht über alle Nutzer
@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db_connection()
    cursor = conn.execute("SELECT id, username, role FROM users")
    users = cursor.fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)

# Registrierung neuer Nutzer (über Admin erreichbar)
@app.route('/admin/register', methods=['GET', 'POST'])
@admin_required
def register_user():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        role = request.form.get("role", "user")  # Standardmäßig "user"
    
        if not username or not password:
            flash("Benutzername und Passwort sind erforderlich!")
            return redirect(url_for('register_user'))
    
        hashed_password = generate_password_hash(password)
    
        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                         (username, hashed_password, role))
            conn.commit()
            flash("Benutzer erfolgreich registriert!")
        except sqlite3.IntegrityError:
            flash("Benutzername bereits vergeben!")
        finally:
            conn.close()
    
        return redirect(url_for('admin_users'))
    
    return render_template('register_user.html')

# Löschen von Nutzern
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash("Benutzer gelöscht!")
    return redirect(url_for('admin_users'))

if __name__ == '__main__':
    init_db()
    # Der Server hört auf allen Interfaces (ideal für den Einsatz auf einem Raspberry Pi im LAN)
    app.run(debug=True, host='0.0.0.0')