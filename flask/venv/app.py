from flask import Flask, request, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os

# === App Setup ===
app = Flask(__name__)

CORS(app)
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Change this in production
jwt = JWTManager(app)


DATABASE = 'user.db'

# === DB Init ===
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
                       
        ''')
        cursor.execute('''
                       
            CREATE TABLE IF NOT EXISTS qr_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    meal_type TEXT,
    date TEXT,
    image_path TEXT,
    claimed BOOLEAN
);
                       
                       
                       
                      ''' )
        conn.commit()

init_db()





# @app.route('/upload_qr', methods=['POST'])
# def upload_qr():
      
#     meal_type = request.form.get('meal_type')
#     date = request.form.get('date')
#     image = request.files.get('qr_image')
#     print("Upload QR data received:", request.form)
#     print("Meal Type:", meal_type)  
#     print("Date:", date)
#     print("Image:", image)

#     if not meal_type or not date or not image:
#         return jsonify({"error": "All fields are required"}), 400

#     filename = secure_filename(image.filename)
#     image_path = os.path.join('static/qr_images', filename)
#     os.makedirs(os.path.dirname(image_path), exist_ok=True)
#     image.save(image_path)

#     with sqlite3.connect(DATABASE) as conn:
#         cursor = conn.cursor()
#         cursor.execute("INSERT INTO qr_codes (meal_type, date, image_path, claimed) VALUES (?, ?, ?, ?)",
#                        (meal_type, date, image_path, False))
#         conn.commit()

#     return jsonify({"message": "QR uploaded successfully", "image_path": image_path}), 200
# @app.route('/upload_qr', methods=['POST'])
# def upload_qr():
#     data = request.get_json(silent=True)  # Returns None if no/invalid JSON, no exception
#     if not data:
#         return jsonify({"error": "Invalid or missing JSON"}), 400

#     meal_type = data.get('meal_type')
#     date = data.get('date')

#     print("meal_type:", meal_type)
#     print("date:", date)

#     if not meal_type or not date:
#         return jsonify({"error": "Missing data"}), 400


@app.route('/upload_qr', methods=['POST'])
def upload_qr():
    meal_type = request.form.get('meal_type')
    date = request.form.get('date')
    image = request.files.get('qr_image')

    if not meal_type or not date or not image:
        return jsonify({"error": "All fields are required"}), 400

    filename = secure_filename(image.filename)
    image_path = os.path.join('static/qr_images', filename)
    os.makedirs(os.path.dirname(image_path), exist_ok=True)
    image.save(image_path)

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        
        cursor.execute("INSERT INTO qr_data (meal_type, date, image_path, claimed) VALUES (?, ?, ?, ?)",
                       (meal_type, date, image_path, False))
        conn.commit()

    return jsonify({"message": "QR uploaded successfully", "image_path": image_path}), 200






@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    print("Signup data received:", data)  # <-- Add this line to debug
    
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'user')

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    hashed_password = generate_password_hash(password)

    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, password, role) VALUES (?, ?, ?)", (email, hashed_password, role))
            conn.commit()
            return jsonify({"message": "User created successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "User already exists"}), 409

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password, role FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()

    if row and check_password_hash(row[0], password):
        role = row[1]
        access_token = create_access_token(identity=email)
        print("User:", email, "Role:", role)  
        return jsonify({
            "message": "Login successful",
            "token": access_token,
            "role": role  
        }), 200
    else:
        return jsonify({"error": "Invalid email or password"}), 401


# === Run App ===
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
