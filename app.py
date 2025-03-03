from flask import Flask, render_template, request, redirect, url_for, session, send_file, jsonify
import mysql.connector
import os
import json
from datetime import datetime
from werkzeug.utils import secure_filename
from ultralytics import YOLO
from authlib.integrations.flask_client import OAuth
import cv2
import zipfile
from werkzeug.security import check_password_hash
from io import BytesIO
from PIL import Image
import base64
import os
from dotenv import load_dotenv

load_dotenv()


app = Flask(__name__)
app.secret_key = 'your_secret_key'

UPLOAD_FOLDER = 'static/uploads'
ANNOTATED_FOLDER = 'static/annotated'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ANNOTATED_FOLDER, exist_ok=True)

# Load YOLOv8 model
model = YOLO("best14.pt")

# Google OAuth Configuration
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("CLIENT_ID"),  # Client ID
    client_secret=os.getenv("CLIENT_SECRET"),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs",
)

import mysql.connector

# MySQL Database Connection (Tanpa .env)
# MySQL Database Connection
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="lung_ct_scan"
    )


# Helper Function: Save Annotated Image
def save_annotated_image(image, filename):
    path = os.path.join(ANNOTATED_FOLDER, filename)
    cv2.imwrite(path, image)
    return path

@app.route('/')
def index():
    if 'user_id' in session or 'google_user' in session:
        return redirect(url_for('workspaces'))
    return redirect(url_for('login'))

import bcrypt
import re
import bcrypt

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Validasi input
        if not username or not password or not email:
            error_message = "All fields are required."
            return render_template('register.html', error=error_message)

        # Validasi email
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            error_message = "Invalid email format."
            return render_template('register.html', error=error_message)

        # Hash password
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Masukkan data ke database
            cursor.execute(
                "INSERT INTO users (username, email, password, google_id) VALUES (%s, %s, %s, NULL)",
                (username, email, hashed_password)
            )
            conn.commit()
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            # Tangani jika username atau email sudah digunakan
            error_message = "Username or email already exists."
            return render_template('register.html', error=error_message)
        except mysql.connector.Error as err:
            return f"Error: {err}"
        finally:
            cursor.close()
            conn.close()

    return render_template('register.html')

# Route to download all detections in a workspace as a ZIP
@app.route('/download_all_detections/<int:workspace_id>', methods=['GET'])
def download_all_detections(workspace_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT image_name, detection_data FROM detections WHERE workspace_id = %s", (workspace_id,))
    detections = cursor.fetchall()
    cursor.close()
    conn.close()

    # Create a ZIP file with all detections
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
        for detection in detections:
            image_name, detection_data = detection
            # Save the detection data as a JSON file in the ZIP
            zip_file.writestr(f"{image_name}_detection.json", detection_data)

    zip_buffer.seek(0)
    return send_file(zip_buffer, as_attachment=True, download_name="detections.zip", mimetype="application/zip")

from io import BytesIO
import zipfile

def download_zip_with_detections(images, filenames, detections_data, zip_name="detections.zip"):
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        for img, name, detections in zip(images, filenames, detections_data):
            # Menulis gambar ke dalam zip
            img_buffer = BytesIO()
            img.save(img_buffer, format="JPEG")
            zf.writestr(name, img_buffer.getvalue())
            
            # Menulis file txt deteksi ke dalam zip
            txt_filename, detection_text = save_detection_to_txt(detections, name)
            zf.writestr(txt_filename, detection_text)
    
    zip_buffer.seek(0)
    return zip_buffer

@app.route('/download_all_detections_zip/<int:workspace_id>')
def download_all_detections_zip(workspace_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Mengambil gambar dan hasil deteksi
    cursor.execute("SELECT image_name, detection_data FROM detections WHERE workspace_id = %s", (workspace_id,))
    detections = cursor.fetchall()
    
    images = []
    filenames = []
    detections_data = []
    
    for detection in detections:
        # Mendapatkan file gambar
        image_name = detection[0]
        image_path = os.path.join("static/annotated", "annotated_"+image_name)  # Sesuaikan path gambar
        img = Image.open(image_path)
        
        # Menambahkan gambar dan hasil deteksi
        images.append(img)
        filenames.append(image_name)
        detections_data.append(json.loads(detection[1]))  # Parsing hasil deteksi JSON
    
    cursor.close()
    conn.close()
    
    # Membuat file ZIP dengan gambar dan file txt hasil deteksi
    zip_buffer = download_zip_with_detections(images, filenames, detections_data)
    
    return send_file(zip_buffer, as_attachment=True, download_name="detections_with_images.zip", mimetype='application/zip')




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        # Ambil data user berdasarkan username
        cursor.execute("SELECT id, password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user:
            # Verifikasi password dengan bcrypt
            if bcrypt.checkpw(password.encode(), user[1].encode()):  # Verifikasi password hash
                session['user_id'] = user[0]
                return redirect(url_for('workspaces'))
            else:
                error_message = "Invalid username or password."
                return render_template('login.html', error=error_message)
        else:
            error_message = "Invalid username or password."
            return render_template('login.html', error=error_message)

    return render_template('login.html')



@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)



@app.route('/login/google/callback')
def authorize_google():
    # Mendapatkan token dari Google OAuth
    token = google.authorize_access_token()
    # Mendapatkan informasi pengguna dari Google
    user_info = google.get('userinfo').json()

    # Cek apakah pengguna sudah terdaftar di database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE google_id = %s", (user_info['id'],))
    user = cursor.fetchone()

    if user:
        # Jika pengguna sudah ada, simpan ID pengguna ke sesi
        session['google_user'] = user_info
        session['user_id'] = user[0]
    else:
        # Jika pengguna belum ada, daftarkan pengguna baru
        cursor.execute("""
            INSERT INTO users (google_id, username, email) 
            VALUES (%s, %s, %s)
        """, (user_info['id'], user_info.get('name'), user_info.get('email')))
        conn.commit()
        
        # Ambil ID pengguna yang baru saja didaftarkan
        cursor.execute("SELECT id FROM users WHERE google_id = %s", (user_info['id'],))
        new_user = cursor.fetchone()
        session['google_user'] = user_info
        session['user_id'] = new_user[0]

    cursor.close()
    conn.close()

    # Redirect ke halaman workspaces setelah login berhasil
    return redirect(url_for('workspaces'))



def save_detection_to_txt(detections, image_name):
    txt_filename = f"{image_name.split('.')[0]}_detection.txt"
    detection_text = ""

    for detection in detections:
        try:
            # Mengambil nilai dari dictionary
            detection_class = detection.get('class', 'Unknown')
            confidence = detection.get('confidence', 'Unknown')
            bounding_box = detection.get('box', 'Unknown')

            # Format deteksi untuk disimpan ke dalam file teks
            detection_text += f"Class: {detection_class}\n"
            detection_text += f"Confidence: {confidence}\n"
            detection_text += f"Bounding Box: {bounding_box}\n"
            detection_text += "-"*50 + "\n"  # Memisahkan setiap deteksi dengan garis

        except Exception as e:
            print(f"Error processing detection: {e}")

    return txt_filename, detection_text



@app.route('/workspace/<int:workspace_id>/download', methods=['POST'])
def download_image(workspace_id):
    if 'user_id' not in session and 'google_user' not in session:
        return redirect(url_for('login'))  # Tidak ada sesi login, arahkan ke halaman login

    # Ambil user_id dari session, sesuai metode login (akun biasa atau Google)
    user_id = session.get('user_id') or session.get('google_user')['id']

    conn = get_db_connection()
    cursor = conn.cursor()

    filename = request.form['filename']
    file_path = os.path.join('static', 'annotated', filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)

    return "File not found!", 404


@app.route('/clear_all_detections/<int:workspace_id>', methods=['POST'])
def clear_all_detections(workspace_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Menghapus seluruh deteksi dalam workspace
    cursor.execute("DELETE FROM detections WHERE workspace_id = %s", (workspace_id,))
    conn.commit()
    
    cursor.close()
    conn.close()
    
    return redirect(url_for('workspace', workspace_id=workspace_id))

@app.route('/workspace/<int:workspace_id>/delete', methods=['POST'])
def delete_image(workspace_id):
    if 'user_id' not in session and 'google_user' not in session:
        return redirect(url_for('login'))  # Tidak ada sesi login, arahkan ke halaman login

    # Ambil user_id dari session, sesuai metode login (akun biasa atau Google)
    user_id = session.get('user_id') or session.get('google_user')['id']

    conn = get_db_connection()
    cursor = conn.cursor()

    filename = request.form['filename']
    # Remove both original and annotated images
    upload_path = os.path.join('static', 'uploads', filename)
    annotated_path = os.path.join('static', 'annotated', filename)

    if os.path.exists(upload_path):
        os.remove(upload_path)
    if os.path.exists(annotated_path):
        os.remove(annotated_path)

    # Remove from database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM detections WHERE workspace_id = %s AND annotated_image_name = %s", (workspace_id, filename))
    conn.commit()
    cursor.close()
    conn.close()

    return redirect(url_for('workspace', workspace_id=workspace_id))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('google_user', None)
    return redirect(url_for('login'))


import time

def process_image(file, workspace_id):
    """Proses gambar untuk deteksi dan simpan hasilnya."""
    # Ambil nama file asli
    original_filename = secure_filename(file.filename)

    # Tambahkan timestamp untuk membuat nama file unik
    timestamp = int(time.time())
    unique_filename = f"{timestamp}_{original_filename}"

    # Simpan gambar asli dengan nama unik
    original_path = os.path.join(UPLOAD_FOLDER, unique_filename)
    file.save(original_path)

    # Proses deteksi dengan YOLO
    img = cv2.imread(original_path)
    results = model.predict(img)
    detections = results[0].boxes

    detection_data = []
    for box in detections:
        x1, y1, x2, y2 = map(int, box.xyxy[0])
        conf = float(box.conf[0])
        cls = int(box.cls[0])
        label = results[0].names[cls]
        detection_data.append({
            "class": label,
            "confidence": conf,
            "box": [x1, y1, x2, y2]
        })

        # Gambar bounding boxes pada gambar
        cv2.rectangle(img, (x1, y1), (x2, y2), (0, 255, 0), 2)
        cv2.putText(img, f"{label} ({conf:.2f})", (x1, y1 - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2)

    # Simpan gambar dengan anotasi dengan nama unik
    annotated_filename = f"annotated_{timestamp}_{original_filename}"
    annotated_path = save_annotated_image(img, annotated_filename)

    # Simpan hasil deteksi ke database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO detections (workspace_id, image_name, annotated_image_name, detection_data) 
        VALUES (%s, %s, %s, %s)
    """, (workspace_id, unique_filename, annotated_filename, json.dumps(detection_data)))
    conn.commit()
    cursor.close()
    conn.close()

    return unique_filename, annotated_filename, detection_data


@app.route('/workspace/<int:workspace_id>', methods=['GET', 'POST'])
def workspace(workspace_id):
    if 'user_id' not in session and 'google_user' not in session:
        return redirect(url_for('login'))  # Tidak ada sesi login, arahkan ke halaman login

    # Ambil user_id dari session, sesuai metode login (akun biasa atau Google)
    user_id = session.get('user_id') or session.get('google_user')['id']

    conn = get_db_connection()
    cursor = conn.cursor()

# Ambil nama workspace berdasarkan workspace_id
    cursor.execute("SELECT name FROM workspaces WHERE id = %s", (workspace_id,))
    workspace_name = cursor.fetchone()

    if not workspace_name:
        return "Workspace not found", 404  # Jika workspace tidak ditemukan
    
    workspace_name = workspace_name[0]


    if request.method == 'POST':
        # Periksa apakah gambar dikirim dari unggahan atau kamera
        file = request.files.get('image')
        if file:
            process_image(file, workspace_id)

    # Ambil semua data deteksi untuk workspace
    cursor.execute("""
        SELECT image_name, annotated_image_name, detection_data, created_at 
        FROM detections 
        WHERE workspace_id = %s
    """, (workspace_id,))
    detections = cursor.fetchall()

    # Parse JSON string kembali ke objek Python
    parsed_detections = []
    for detection in detections:
        image_name = detection[0]
        annotated_image_name = detection[1]
        detection_data = json.loads(detection[2])  # Convert JSON string ke dict Python
        created_at = detection[3]
        parsed_detections.append((image_name, annotated_image_name, detection_data, created_at))

    cursor.close()
    conn.close()
    # return render_template('workspace.html', workspace_id=workspace_id, detections=parsed_detections)
    return render_template('workspace.html', workspace_id=workspace_id, workspace_name=workspace_name, detections=parsed_detections)


@app.route('/workspaces', methods=['GET', 'POST'])
def workspaces():
    if 'user_id' not in session and 'google_user' not in session:
        return redirect(url_for('login'))  # Tidak ada sesi login, arahkan ke halaman login

    # Ambil user_id dari session, sesuai metode login (akun biasa atau Google)
    user_id = session.get('user_id') or session.get('google_user')['id']

    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        name = request.form['name']
        
        # Validasi input workspace
        if not name:
            error_message = "Workspace name is required."
            return render_template('workspaces.html', error=error_message, workspaces=get_user_workspaces(user_id))

        # Insert workspace baru ke database
        cursor.execute("INSERT INTO workspaces (user_id, name) VALUES (%s, %s)", (user_id, name))
        conn.commit()

        # Redirect ke halaman workspaces setelah workspace dibuat
        return redirect(url_for('workspaces'))

    # Ambil daftar workspaces milik pengguna
    workspaces = get_user_workspaces(user_id)

    cursor.close()
    conn.close()
    
    return render_template('workspaces.html', workspaces=workspaces)

def get_user_workspaces(user_id):
    """ Fungsi untuk mengambil daftar workspaces yang dimiliki oleh user """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM workspaces WHERE user_id = %s", (user_id,))
    workspaces = cursor.fetchall()
    cursor.close()
    conn.close()
    return workspaces


# Route to delete a workspace and all its detections
@app.route('/delete_workspace/<int:workspace_id>', methods=['POST'])
def delete_workspace(workspace_id):
    # Cek apakah user yang login memiliki workspace ini
    if 'user_id' not in session and 'google_user' not in session:
        return redirect(url_for('login'))  # Jika tidak ada sesi login, arahkan ke halaman login

    # Ambil user_id dari session, sesuai metode login (akun biasa atau Google)
    user_id = session.get('user_id') or session.get('google_user')['id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # Pastikan workspace yang akan dihapus milik user yang login
    cursor.execute("SELECT user_id FROM workspaces WHERE id = %s", (workspace_id,))
    workspace_owner = cursor.fetchone()

    if workspace_owner and workspace_owner[0] == user_id:
        # Delete all detections in this workspace
        cursor.execute("DELETE FROM detections WHERE workspace_id = %s", (workspace_id,))
        conn.commit()

        # Now delete the workspace itself
        cursor.execute("DELETE FROM workspaces WHERE id = %s", (workspace_id,))
        conn.commit()
    
    cursor.close()
    conn.close()
    return redirect(url_for('workspaces'))


@app.route('/workspace/<int:workspace_id>/capture_upload', methods=['POST'])
def capture_upload(workspace_id):
    if 'user_id' not in session and 'google_user' not in session:
        return redirect(url_for('login'))  # Tidak ada sesi login, arahkan ke halaman login

    # Ambil user_id dari session, sesuai metode login (akun biasa atau Google)
    user_id = session.get('user_id') or session.get('google_user')['id']

    conn = get_db_connection()
    cursor = conn.cursor()

    file = request.files.get('image')
    if file:
        process_image(file, workspace_id)
        # Redirect ke halaman workspace untuk memperbarui tampilan
        return redirect(url_for('workspace', workspace_id=workspace_id))

    return redirect(url_for('workspace', workspace_id=workspace_id))



if __name__ == '__main__':
    app.run(debug=True)
