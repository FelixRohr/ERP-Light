from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash, send_file
import sqlite3, bcrypt, os, io
from datetime import datetime
from functools import wraps
import xlsxwriter
import base64

from datetime import timezone
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Image
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4

app = Flask(__name__)
app.secret_key = 'dein_geheimer_schluessel'  # In der Produktion bitte einen sicheren Schlüssel verwenden!

DB_PATH = None

#Currently read only
#DB_DIR ="/home/funk-erp/Documents/ELW-CLOUD/Southside/SSF 2025/Datenbank Funkgeraete"

#working on pi
DB_DIR = "/home/funk-erp/"

# working on test pc
#DB_DIR = os.path.join("C:\\", "git")

DB_PATH_Backup = (r"SSF2025_Funkgeräte.db")

status_signed_out = "checked_out"
status_signed_in = "available"

def list_available_databases():
    if not os.path.exists(DB_DIR):
        print("path non existend")
        return [DB_PATH_Backup] 
    return [f for f in os.listdir(DB_DIR) if f.endswith(".db") and os.path.isfile(os.path.join(DB_DIR, f))]




def get_db_connection(db_path):
    
    conn = sqlite3.connect(db_path, timeout=10, check_same_thread=False)
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
    conn = get_db_connection(DB_PATH_Backup)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        inventory_number TEXT UNIQUE NOT NULL,
        user TEXT,
        checked_out_at TEXT,
        checked_in_at TEXT,
        status TEXT,
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
    #Generate Admin User with Password "admin" if no admin is available
    cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    if cursor.fetchone() is None:
        salt = bcrypt.gensalt()
        admin_password = bcrypt.hashpw("admin".encode('utf-8'), salt)
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

@app.route('/export_pdf')
def export_pdf():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    conn = get_db_connection(session["db_path"])
    devices = conn.execute("SELECT * FROM devices").fetchall()
    conn.close()

    data = [["ID", "User", "Ausgeliehen", "Zurückgegeben", "Status", "Unterschrift"]]
    for device in devices:
        row = [device["inventory_number"], device["user"], device["checked_out_at"], device["checked_in_at"], device["status"]]
        sig = device["signature"]
        
        if sig and sig.startswith("data:image/"):
            try:
                img_data = io.BytesIO(base64.b64decode(sig.split(",")[1]))
                img = Image(img_data, width=80, height=40)
                row.append(img)
            except Exception as e:
                row.append(f"Fehler{e}")
        else: 
            row.append(sig or "")
        data.append(row)

    table = Table(data)
    table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey)]))
    elements = [table]
    doc.build(elements)
    buffer.seek(0)
    now = datetime.now(timezone.utc).isoformat()
    human_now = format_timestamp(now)
    return send_file(buffer, as_attachment=True, download_name=f"Funkdatenbank_export_{human_now}.pdf", mimetype="application/pdf")


@app.route('/export_ek')
@admin_required
def export_excel():
    conn = get_db_connection(session["db_path"])
    cursor = conn.execute("SELECT * FROM devices")
    devices = cursor.fetchall()
    conn.close()

    output = io.BytesIO()
    workbook = xlsxwriter.Workbook(output, {'in_memory': True})
    worksheet = workbook.add_worksheet("Geräte")

    headers = ["ID", "Inventory Number", "User", "Ausgeliehen am", "Zurückgegeben am", "Unterschrift"]
    for col_num, header in enumerate(headers):
        worksheet.write(0, col_num, header)

    for row_num, device in enumerate(devices, start=1):
        for col_num, key in enumerate(["id", "inventory_number", "user", "checked_out_at", "checked_in_at"]):
            worksheet.write(row_num, col_num, device[key])
        
        # Signature-Spalte
        sig = device["signature"]
        if sig and sig.startswith("data:image/"):
            try:
                image_data = base64.b64decode(sig.split(",")[1])
                image_stream = io.BytesIO(image_data)
                worksheet.insert_image(row_num, 5, "signature.png", {'image_data': image_stream, 'x_scale': 0.5, 'y_scale': 0.5})
            except Exception as e:
                worksheet.write(row_num, 5, "[Bild defekt]")
        else:
            worksheet.write(row_num, 5, sig if sig else "")

    workbook.close()
    output.seek(0)

    return send_file(output, as_attachment=True, download_name="geraete_export.xlsx", mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

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
        
        db_name = request.form.get("db_name")
        
        try:
            session["db_path"] = os.path.join(DB_DIR, db_name)
            print(session["db_path"])
        except:
            pass

        if not os.path.exists(session["db_path"]):
            session["db_path"] = DB_PATH_Backup
            return "⚠️ Die ausgewählte Datenbank existiert nicht oder ist nicht erreichbar.", 404

        
        conn = get_db_connection(session["db_path"])
        cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
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
    databases = list_available_databases()
    return render_template("login.html", databases=databases)



@app.route('/logout')
def logout():
    session.clear()
    flash("Abgemeldet!")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def user_area():
    conn = get_db_connection(session["db_path"])
    
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
    conn = get_db_connection(session["db_path"])
    cursor = conn.execute("SELECT * FROM devices")
    devices = [dict(row) for row in cursor.fetchall()]
    conn.close()
    for device in devices:
        device['checked_out_at'] = format_timestamp(device['checked_out_at'])
        device['checked_in_at'] = format_timestamp(device['checked_in_at'])
        device['status'] = device['status']
    return render_template('admin.html', devices=devices)


@app.route("/admin/update_device/<int:device_id>", methods=["POST"])
def update_device(device_id):
    data = request.json
    inventory_number = data.get("inventory_number")
    user = data.get("user")
    checked_out_at = data.get("checked_out_at")
    checked_in_at = data.get("checked_in_at")
    status = data.get("status")

    conn = get_db_connection(session["db_path"])
    cursor = conn.execute("SELECT id FROM devices WHERE id = ?", (device_id,))
    device = cursor.fetchone()

    if not device:
        return jsonify({"success": False, "error": "Gerät nicht gefunden"}), 404

    conn.execute("""
        UPDATE devices 
        SET inventory_number = ?, user = ?, checked_out_at = ?, checked_in_at = ?, status = ?
        WHERE id = ?
    """, (inventory_number, user, checked_out_at, checked_in_at, status, device_id))

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
    status = data.get('status')
    
    if not inventory_number or not borrower or not signature or signature.strip() == "":
        return jsonify({"error": "Inventarnummer, Borrower und Unterschrift sind erforderlich."}), 400
    
    conn = get_db_connection(session["db_path"])
    cursor = conn.execute("SELECT * FROM devices WHERE inventory_number = ?", (inventory_number,))
    device = cursor.fetchone()
    
    if device and device['user'] is not None:
        conn.close()
        return jsonify({"error": "Gerät bereits ausgeliehen"}), 400
    
    now = datetime.now(timezone.utc).isoformat()
    human_now = format_timestamp(now)
    if device:
        conn.execute("""
           UPDATE devices
           SET user = ?, checked_out_at = ?, checked_in_at = ?, status= ?, signature = ?
           WHERE inventory_number = ?
        """, (borrower, human_now, "-", status_signed_out, signature, inventory_number))
    else:
        conn.execute("""
           INSERT INTO devices (inventory_number, user, checked_out_at, checked_in_at, status, signature)
           VALUES (?, ?, ?, ?, ?, ?)
        """, (inventory_number, borrower, human_now, "-", status_signed_out,  signature))
    
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

    conn = get_db_connection(session["db_path"])
    cursor = conn.execute("SELECT * FROM devices WHERE inventory_number = ?", (inventory_number,))
    device = cursor.fetchone()

    if not device:
        conn.close()
        return jsonify({"error": "Gerät existiert nicht"}), 404

    if device['status'] != status_signed_out:
        conn.close()
        return jsonify({"error": "Gerät ist nicht ausgeliehen"}), 400


    now = datetime.now(timezone.utc).isoformat()
    human_now = format_timestamp(now)
    conn.execute("UPDATE devices SET checked_in_at = ?, user = ?, checked_out_at = ?, status = ? WHERE inventory_number = ?", (human_now, None, None, status_signed_in, inventory_number))
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
    
    conn = get_db_connection(session["db_path"])
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
    status = data.get("status")
    
    if not device_id:
        return jsonify({"error": "Device ID is required"}), 400

    parsed_checked_out_at = parse_timestamp_field(checked_out_at)
    parsed_checked_in_at = parse_timestamp_field(checked_in_at)
    
    conn = get_db_connection(session["db_path"])
    conn.execute("""
        UPDATE devices
        SET inventory_number = ?, user = ?, checked_out_at = ?, checked_in_at = ?, status = ?
        WHERE id = ?
    """, (inventory_number, user_assigned, parsed_checked_out_at, parsed_checked_in_at, status, device_id))
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

    conn = get_db_connection(session["db_path"])
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
    conn = get_db_connection(session["db_path"])
    cursor = conn.execute("SELECT * FROM devices WHERE inventory_number = ?", (inventory_number,))
    device = cursor.fetchone()
    if device and device['user'] is not None:
        conn.close()
        return jsonify({"error": "Gerät wurde bereits ausgeliehen."}), 400
    now = datetime.now(timezone.utc).isoformat()
    # Konvertiere den ISO-Zeitstempel in ein menschenlesbares Format:
    human_now = format_timestamp(now)
    if device:
        conn.execute(
            "UPDATE devices SET user = ?, checked_out_at = ?, checked_in_at = NULL, status = ? WHERE inventory_number = ?",
            (user, human_now, inventory_number, status_signed_out))
    else:
        conn.execute(
            "INSERT INTO devices (inventory_number, user, checked_out_at, checked_in_at, status = ? ) VALUES (?, ?, ?, ?)",
            (inventory_number, user, human_now, status_signed_out, "-"))
    conn.commit()
    conn.close()
    return jsonify({
        "message": f"Gerät {inventory_number} wurde erfolgreich an {user} ausgecheckt (Admin).",
        "checked_out_at": human_now,  # Rückgabe des formatierten Zeitstempels
        "status": status_signed_in
    }), 200

# Admin Check-in ohne Unterschrift (Gerät wird als "Verfügbar" markiert)
@app.route('/admin/check_in', methods=['POST'])
@admin_required
def admin_check_in():
    data = request.json
    inventory_number = data.get('inventory_number')
    if not inventory_number:
        return jsonify({"error": "Inventarnummer ist erforderlich."}), 400
    conn = get_db_connection(session["db_path"])
    cursor = conn.execute("SELECT * FROM devices WHERE inventory_number = ?", (inventory_number,))
    device = cursor.fetchone()
    if not device:
        conn.close()
        return jsonify({"error": "Gerät existiert nicht."}), 404
    if device['user'] is None:
        conn.close()
        return jsonify({"error": "Gerät ist bereits verfügbar."}), 400
    now = datetime.now(timezone.utc).isoformat()
    human_now = format_timestamp(now)
    conn.execute("UPDATE devices SET checked_in_at = ?, status = ? WHERE inventory_number = ?", (human_now, status_signed_in, inventory_number))
    conn.commit()
    conn.close()
    return jsonify({
        "message": f"Gerät {inventory_number} wurde erfolgreich eingecheckt (Admin).",
        "checked_in_at": human_now,  # Rückgabe des formatierten Rückgabezeitpunkts
        "status": status_signed_in 
    }), 200
# --- Nutzerverwaltung im Admin-Bereich ---

@app.route("/admin/toggle_status/<int:device_id>", methods=["POST"])
def toggle_status(device_id):
    from datetime import datetime

    conn = get_db_connection(session["db_path"])
    cursor = conn.execute("SELECT user FROM devices WHERE id = ?", (device_id,))
    device = cursor.fetchone()

    if not device:
        return jsonify({"success": False, "error": "Gerät nicht gefunden"}), 404

    if device["user"]:
        # Gerät wird zurückgegeben -> Unterschrift löschen
        new_status = None
        checked_in_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("UPDATE devices SET checked_in_at = ?, status = ?, signature = NULL WHERE id = ?", (checked_in_at, status_signed_in, device_id))
        state = status_signed_in
    else:
        
        admin_name = session.get("username")  # Holt den angemeldeten Admin aus der Session
        if not admin_name:
            return jsonify({"success": False, "error": "Admin nicht erkannt!"}), 400

        user_name = request.json.get("user")
        if not user_name:
            return jsonify({"success": False, "error": "Bitte einen Benutzer eintragen, bevor das Gerät ausgeliehen wird."}), 400

        # Gerät ausleihen -> Benutzername als Unterschrift speichern
        new_status = "checked_out"
        checked_out_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # **Hier stellen wir sicher, dass checked_in_at gelöscht wird!**
        conn.execute("UPDATE devices SET user = ?, checked_out_at = ?, checked_in_at = NULL, status = ?, signature = ? WHERE id = ?", 
                     (user_name, checked_out_at, status_signed_out, admin_name, device_id))
        state = status_signed_out

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "new_status": new_status,
        "checked_out_at": checked_out_at if new_status == "checked_out" else None,
        "checked_in_at": checked_in_at if new_status is None else None,
        "status": state,
        "signature": user_name if new_status == "checked_out" else None
    }), 200
    
@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db_connection(session["db_path"])
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
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    conn = get_db_connection(session["db_path"])
    try:
        conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    (username, hashed_password, role))
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        flash("Benutzername bereits vergeben!")
    finally:
        conn.close()
    conn.close()
    return redirect(url_for('admin_users'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    conn = get_db_connection(session["db_path"])
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash("Benutzer gelöscht!")
    return redirect(url_for('admin_users'))

@app.route('/admin/delete_device/<int:device_id>', methods=['POST'])
@admin_required
def delete_device(device_id):
    conn = get_db_connection(session["db_path"])
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

    conn = get_db_connection(session["db_path"])
    cursor = conn.execute("SELECT user, status FROM devices WHERE inventory_number = ?", (inventory_number,))
    device = cursor.fetchone()
    conn.close()

    if not device or device['status'] == status_signed_in:
        return jsonify({"status": "available"})
    else:
        return jsonify({"status": "checked_out"})
    

@app.route("/admin/get_devices")
def get_devices():
    conn = get_db_connection(session["db_path"])
    cursor = conn.execute("SELECT * FROM devices")
    devices = cursor.fetchall()
    conn.close()
    return jsonify([dict(device) for device in devices])

@app.route("/change_password", methods=["POST"])
@login_required
def change_password():
    data = request.json
    current_password = data.get("current_password")
    new_password = data.get("new_password")

    conn = get_db_connection(session["db_path"])
    cursor = conn.execute("SELECT password FROM users WHERE username = ?", (session["username"],))
    user = cursor.fetchone()
    if not user or not bcrypt.checkpw(current_password.encode('utf-8'), user['password']):
        return jsonify({"success": False, "error": "Aktuelles Passwort ist falsch!"}), 400

    salt = bcrypt.gensalt()
    hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), salt)
    conn.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_new_password, session["username"]))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Passwort erfolgreich geändert!"})


if __name__ == '__main__':
    init_db()
    import socket
    if 'liveconsole' not in socket.gethostname():    
        app.run(host='0.0.0.0', port=5000, debug=False)
