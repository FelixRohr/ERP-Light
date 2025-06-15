from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
import sqlite3
from datetime import datetime
import base64
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'dein_geheimer_schluessel'  # In der Produktion bitte einen sicheren Schlüssel verwenden!

DB_PATH = "devices.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def format_timestamp(timestamp):
    """Konvertiert einen ISO-Zeitstempel in ein menschenlesbares Format.
       Falls der Wert bereits formatiert ist, wird er unverändert zurückgegeben."""
    if timestamp:
        try:
            dt = datetime.fromisoformat(timestamp)
            return dt.strftime("%d. %B %Y, %H:%M Uhr")
        except ValueError:
            # Vermutlich ist der Timestamp bereits formatiert
            return timestamp
    return "-"

def parse_timestamp_field(ts):
    """
    Versucht, einen eingegebenen Zeitstempel zu parsen. 
    Falls die Zeichenkette nicht im ISO-Format vorliegt, wird versucht,
    sie gemäß "%d. %B %Y, %H:%M Uhr" oder "%d. %b %Y, %H:%M Uhr" zu interpretieren und in ISO umzuwandeln.
    Gibt im Fehlerfall den Originalstring zurück.
    """
    if not ts or ts.strip() == "":
        return None
    try:
        datetime.fromisoformat(ts)
        return ts
    except ValueError:
        try:
            dt = datetime.strptime(ts, "%d. %B %Y, %H:%M Uhr")
            return dt.isoformat()
        except ValueError:
            try:
                dt = datetime.strptime(ts, "%d. %b %Y, %H:%M Uhr")
                return dt.isoformat()
            except ValueError:
                return ts

def init_db():
    """Erstellt die Tabellen devices und users, falls diese noch nicht existieren.
       Legt einen Default-Admin an, falls nicht vorhanden."""
    conn = get_db_connection()
    cursor = conn.cursor()
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
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )
    """)
    cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    if cursor.fetchone() is None:
        admin_password = generate_password_hash("admin")
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                       ("admin", admin_password, "admin"))
    conn.commit()
    conn.close()

# --- Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Bitte anmelden!")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('role') != 'admin':
            flash("Admin Rechte benötigt!")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routen & Endpoints ---

@app.route('/')
def index():
    if 'username' in session:
        if session.get('role') == "admin":
            return redirect(url_for('admin_area'))
        else:
            return redirect(url_for('user_area'))
    return redirect(url_for('login'))

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
            session.permanent = False  # Sitzung nur für den aktuellen Browser-Tab aktiv
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

@app.route('/dashboard')
@login_required
def user_area():
    conn = get_db_connection()
    
    # Liste der registrierten Benutzer abrufen
    cursor = conn.execute("SELECT username FROM users")
    borrowers = [row['username'] for row in cursor.fetchall()]
    conn.close()

    # Adminprüfung über Session
    return render_template('dashboard.html', borrowers=borrowers, is_admin=(session.get('role') == 'admin'))

# Admin Geräteverwaltung
@app.route('/admin')
@admin_required
def admin_area():
    conn = get_db_connection()
    cursor = conn.execute("SELECT * FROM devices")
    devices = [dict(row) for row in cursor.fetchall()]
    conn.close()
    for device in devices:
        device['checked_out_at'] = format_timestamp(device['checked_out_at'])
        device['checked_in_at'] = format_timestamp(device['checked_in_at'])
    return render_template('admin.html', devices=devices)


@app.route("/admin/update_device/<int:device_id>", methods=["POST"])
def update_device(device_id):
    data = request.json
    inventory_number = data.get("inventory_number")
    user = data.get("user")
    checked_out_at = data.get("checked_out_at")
    checked_in_at = data.get("checked_in_at")

    conn = get_db_connection()
    cursor = conn.execute("SELECT id FROM devices WHERE id = ?", (device_id,))
    device = cursor.fetchone()

    if not device:
        return jsonify({"success": False, "error": "Gerät nicht gefunden"}), 404

    conn.execute("""
        UPDATE devices 
        SET inventory_number = ?, user = ?, checked_out_at = ?, checked_in_at = ?
        WHERE id = ?
    """, (inventory_number, user, checked_out_at, checked_in_at, device_id))

    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Gerät wurde erfolgreich aktualisiert."})

# Check-out (User): bleibt unverändert


@app.route('/check_out', methods=['POST'])
@login_required
def check_out():
    data = request.json
    inventory_number = data.get('inventory_number')
    borrower = data.get('borrower')
    signature = data.get('signature')
    
    if not inventory_number or not borrower or not signature or signature.strip() == "":
        return jsonify({"error": "Inventarnummer, Borrower und Unterschrift sind erforderlich."}), 400
    
    conn = get_db_connection()
    cursor = conn.execute("SELECT * FROM devices WHERE inventory_number = ?", (inventory_number,))
    device = cursor.fetchone()
    
    if device and device['user'] is not None:
        conn.close()
        return jsonify({"error": "Gerät bereits ausgeliehen"}), 400
    
    now = datetime.utcnow().isoformat()
    if device:
        conn.execute("""
           UPDATE devices
           SET user = ?, checked_out_at = ?, checked_in_at = NULL, signature = ?
           WHERE inventory_number = ?
        """, (borrower, now, signature, inventory_number))
    else:
        conn.execute("""
           INSERT INTO devices (inventory_number, user, checked_out_at, signature)
           VALUES (?, ?, ?, ?)
        """, (inventory_number, borrower, now, signature))
    
    conn.commit()
    conn.close()
    return jsonify({"message": f"Gerät {inventory_number} erfolgreich an {borrower} vergeben."}), 200

# Check-in (User): bleibt unverändert

@app.route('/check_in', methods=['POST'])
@login_required
def check_in():
    data = request.json
    inventory_number = data.get('inventory_number')
    
    if not inventory_number:
        return jsonify({"error": "Inventarnummer erforderlich"}), 400

    conn = get_db_connection()
    cursor = conn.execute("SELECT * FROM devices WHERE inventory_number = ?", (inventory_number,))
    device = cursor.fetchone()

    if not device:
        conn.close()
        return jsonify({"error": "Gerät existiert nicht"}), 404

    if device['user'] is None:
        conn.close()
        return jsonify({"error": "Gerät ist nicht ausgeliehen"}), 400

    now = datetime.utcnow().isoformat()
    conn.execute("UPDATE devices SET user = NULL, checked_in_at = ? WHERE inventory_number = ?", (now, inventory_number))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Gerät {inventory_number} erfolgreich zurückgegeben."}), 200

# Unterschrift speichern (optional)
@app.route('/save_signature', methods=["POST"])
@login_required
def save_signature():
    data = request.json
    signature_data = data.get("signature")
    inventory_number = data.get("inventory_number")
    if not signature_data or not inventory_number:
        return jsonify({"error": "Signature and inventory number are required"}), 400
    
    conn = get_db_connection()
    conn.execute("UPDATE devices SET signature = ? WHERE inventory_number = ?", (signature_data, inventory_number))
    conn.commit()
    conn.close()
    return jsonify({"message": "Unterschrift gespeichert"}), 200

# Gerät bearbeiten (Admin)
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

    parsed_checked_out_at = parse_timestamp_field(checked_out_at)
    parsed_checked_in_at = parse_timestamp_field(checked_in_at)
    
    conn = get_db_connection()
    conn.execute("""
        UPDATE devices
        SET inventory_number = ?, user = ?, checked_out_at = ?, checked_in_at = ?
        WHERE id = ?
    """, (inventory_number, user_assigned, parsed_checked_out_at, parsed_checked_in_at, device_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Gerät aktualisiert"}), 200

# Neues Gerät hinzufügen (Admin)
@app.route('/admin/add_device', methods=['POST'])
@admin_required
def add_device():
    data = request.json
    inventory_number = data.get('inventory_number')
    if not inventory_number:
        return jsonify({"error": "Inventarnummer is required"}), 400

    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO devices (inventory_number) VALUES (?)", (inventory_number,))
        conn.commit()
        conn.close()
        return jsonify({"message": f"Gerät {inventory_number} hinzugefügt."}), 200
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Gerät existiert bereits."}), 400

# --- Neue Endpunkte: Admin Check-out und Check-in ohne Unterschrift ---
# Admin Check-out ohne Unterschrift (Gerät wird als "In Benutzung" markiert)
@app.route('/admin/check_out', methods=['POST'])
@admin_required
def admin_check_out():
    data = request.json
    inventory_number = data.get('inventory_number')
    user = data.get('user')
    if not inventory_number or not user:
        return jsonify({"error": "Inventarnummer und Benutzer sind erforderlich."}), 400
    conn = get_db_connection()
    cursor = conn.execute("SELECT * FROM devices WHERE inventory_number = ?", (inventory_number,))
    device = cursor.fetchone()
    if device and device['user'] is not None:
        conn.close()
        return jsonify({"error": "Gerät wurde bereits ausgeliehen."}), 400
    now = datetime.utcnow().isoformat()
    # Konvertiere den ISO-Zeitstempel in ein menschenlesbares Format:
    human_now = format_timestamp(now)
    if device:
        conn.execute(
            "UPDATE devices SET user = ?, checked_out_at = ?, checked_in_at = NULL WHERE inventory_number = ?",
            (user, now, inventory_number))
    else:
        conn.execute(
            "INSERT INTO devices (inventory_number, user, checked_out_at) VALUES (?, ?, ?)",
            (inventory_number, user, now))
    conn.commit()
    conn.close()
    return jsonify({
        "message": f"Gerät {inventory_number} wurde erfolgreich an {user} ausgecheckt (Admin).",
        "checked_out_at": human_now  # Rückgabe des formatierten Zeitstempels
    }), 200

# Admin Check-in ohne Unterschrift (Gerät wird als "Verfügbar" markiert)
@app.route('/admin/check_in', methods=['POST'])
@admin_required
def admin_check_in():
    data = request.json
    inventory_number = data.get('inventory_number')
    if not inventory_number:
        return jsonify({"error": "Inventarnummer ist erforderlich."}), 400
    conn = get_db_connection()
    cursor = conn.execute("SELECT * FROM devices WHERE inventory_number = ?", (inventory_number,))
    device = cursor.fetchone()
    if not device:
        conn.close()
        return jsonify({"error": "Gerät existiert nicht."}), 404
    if device['user'] is None:
        conn.close()
        return jsonify({"error": "Gerät ist bereits verfügbar."}), 400
    now = datetime.utcnow().isoformat()
    human_now = format_timestamp(now)
    conn.execute("UPDATE devices SET user = NULL, checked_in_at = ? WHERE inventory_number = ?", (now, inventory_number))
    conn.commit()
    conn.close()
    return jsonify({
        "message": f"Gerät {inventory_number} wurde erfolgreich eingecheckt (Admin).",
        "checked_in_at": human_now  # Rückgabe des formatierten Rückgabezeitpunkts
    }), 200
# --- Nutzerverwaltung im Admin-Bereich ---

@app.route("/admin/toggle_status/<int:device_id>", methods=["POST"])
def toggle_status(device_id):
    from datetime import datetime

    conn = get_db_connection()
    cursor = conn.execute("SELECT user FROM devices WHERE id = ?", (device_id,))
    device = cursor.fetchone()

    if not device:
        return jsonify({"success": False, "error": "Gerät nicht gefunden"}), 404

    if device["user"]:
        # Gerät zurückgegeben → Unterschrift löschen
        new_status = None
        checked_in_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("UPDATE devices SET user = ?, checked_in_at = ?, signature = NULL WHERE id = ?", (new_status, checked_in_at, device_id))
    else:
        # Prüfen, ob ein Benutzername vorhanden ist
        user_name = request.json.get("user")
        if not user_name:
            return jsonify({"success": False, "error": "Bitte einen Benutzer eintragen, bevor das Gerät ausgeliehen wird."}), 400

        # Gerät ausgeliehen
        new_status = "checked_out"
        checked_out_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        checked_in_at = "—"
        conn.execute("UPDATE devices SET user = ?, checked_out_at = ? WHERE id = ?", (user_name, checked_out_at, device_id))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "new_status": new_status,
        "checked_out_at": checked_out_at if new_status == "checked_out" else None,
        "checked_in_at": checked_in_at if new_status is None else None,
        "signature_cleared": True if new_status is None else False
    })
    
@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db_connection()
    cursor = conn.execute("SELECT id, username, role FROM users")
    users = cursor.fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)

@app.route('/admin/register', methods=['GET', 'POST'])
@admin_required
def register_user():
    if request.method != 'POST':
        return render_template('register_user.html')
    username = request.form.get("username")
    password = request.form.get("password")
    role = request.form.get("role", "user")
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

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash("Benutzer gelöscht!")
    return redirect(url_for('admin_users'))

@app.route('/admin/delete_device/<int:device_id>', methods=['POST'])
@admin_required
def delete_device(device_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Gerät erfolgreich gelöscht."}), 200

@app.route('/device_status')
@login_required
def device_status():
    inventory_number = request.args.get('inventory_number')
    if not inventory_number:
        return jsonify({"error": "Inventarnummer fehlt"}), 400
    conn = get_db_connection()
    cursor = conn.execute("SELECT user FROM devices WHERE inventory_number = ?", (inventory_number,))
    device = cursor.fetchone()
    conn.close()
    # Gerät existiert nicht oder ist verfügbar (user ist NULL)
    if not device or device['user'] is None:
        return jsonify({"status": "available"})
    else:
        return jsonify({"status": "checked_out"})

if __name__ == '__main__':
    init_db()
    import socket
    if 'liveconsole' not in socket.gethostname():
        app.run(host='0.0.0.0', port=5000, debug=True)
