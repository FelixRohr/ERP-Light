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
    Fügt einen Default-Admin hinzu (Benutzer: admin, Passwort: admin). In der Produktion unbedingt anpassen!"""
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
    # Prüfen, ob Admin bereits existiert; falls nicht, ein Default-Admin anlegen
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

# Startseite leitet entweder zum Login oder direkt in den Benutzer- bzw. Adminbereich weiter
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

# Benutzerbereich (Dashboard)
@app.route('/dashboard')
@login_required
def user_area():
    return render_template('dashboard.html')

# Adminbereich: Übersicht aller Geräte, Möglichkeit Einträge zu editieren
@app.route('/admin')
@admin_required
def admin_area():
    conn = get_db_connection()
    cursor = conn.execute("SELECT * FROM devices")
    devices = cursor.fetchall()
    conn.close()
    return render_template('admin.html', devices=devices)

# API-Endpunkt: Gerät ausleihen bzw. auschecken
@app.route('/check_out', methods=['POST'])
@login_required
def check_out():
    data = request.json
    inventory_number = data.get('inventory_number')
    user_name = session.get('username')  # Der aktuell angemeldete Benutzer
    
    if not inventory_number:
        return jsonify({"error": "Inventory number is required"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat()
    try:
        # Bei neuem Gerät wird ein Eintrag erstellt
        cursor.execute("""
        INSERT INTO devices (inventory_number, user, checked_out_at)
        VALUES (?, ?, ?)
        """, (inventory_number, user_name, now))
    except sqlite3.IntegrityError:
        # Existenter Eintrag: Update der Checkout-Informationen
        cursor.execute("""
        UPDATE devices
        SET user = ?, checked_out_at = ?, checked_in_at = NULL
        WHERE inventory_number = ?
        """, (user_name, now, inventory_number))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Device {inventory_number} checked out by {user_name}"}), 200

# API-Endpunkt: Gerät zurückgeben bzw. einchecken
@app.route('/check_in', methods=['POST'])
@login_required
def check_in():
    data = request.json
    inventory_number = data.get('inventory_number')
    
    if not inventory_number:
        return jsonify({"error": "Inventory number is required"}), 400
    
    now = datetime.utcnow().isoformat()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE devices SET user = NULL, checked_in_at = ? WHERE inventory_number = ?
    """, (now, inventory_number))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Device {inventory_number} checked in"}), 200

# Unterschriften-Speicherung (das Signature-Bild wird als Base64-String in der DB abgelegt)
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

if __name__ == '__main__':
    init_db()
    # Der Server hört auf allen Interfaces (ideal für einen Raspberry Pi im lokalen Netzwerk)
    app.run(debug=True, host='0.0.0.0')
