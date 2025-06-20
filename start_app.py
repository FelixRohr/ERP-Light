import sys
import os
import subprocess
import platform


def ensure_requirements():
    if not os.path.exists("requirements.txt"):
        print("⚙️ requirements.txt nicht gefunden – wird erstellt...")
        subprocess.run([sys.executable, "-m", "pip", "freeze"], stdout=open("requirements.txt", "w"))

    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

def start_server():
    os.environ["FLASK_APP"] = "App.py"
    os.environ["FLASK_ENV"] = "production"

    system = platform.system().lower()

    if "windows" in system:
        print("🔧 Starte Server mit waitress unter Windows...")
        subprocess.run([
            sys.executable,
            "-m", "waitress",
            "--host=0.0.0.0",
            "--port=5000",
            "App:app"
        ])
    else:
        print("🔧 Starte Server mit gunicorn unter Linux...")
        subprocess.run([
            "venv/bin/gunicorn",
            "--bind", "0.0.0.0:5000",
            "App:app"
        ])

if __name__ == "__main__":
    ensure_requirements()
    start_server()

