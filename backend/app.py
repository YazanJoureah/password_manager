from flask import Flask, jsonify, request
from flask_cors import CORS
from Crypto.Cipher import AES
import os
import base64
import sqlite3

app = Flask(__name__)
CORS(app)

app.secret_key = os.getenv('SECRET_KEY')

def init_db():
    with sqlite3.connect('passwords.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS passwords
        (id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        password TEXT NOT NULL)''')

init_db()

def encrypt_password(password):
    key = os.urandom(16)  # Generate a random AES key
    cipher = AES.new(key, AES.MODE_EAX)  # Create a new AES cipher
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())  # Encrypt the password
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()  # Encode and return the result

def decrypt_password(encrypted):
    encrypted = base64.b64decode(encrypted)  # Decode the base64 string
    nonce, tag, ciphertext = encrypted[:16], encrypted[16:32], encrypted[32:]  # Extract components
    key = os.urandom(16)  # NOTE: This should be securely managed
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)  # Create cipher with nonce
    return cipher.decrypt_and_verify(ciphertext, tag).decode()  # Decrypt and verify


@app.route('/api/passwords', methods=['GET', 'POST'])

def manage_passwords():
    if request.method == 'POST':
        data = request.json  # Get JSON data from the request
        name = data.get('name')  # Extract service name
        password = encrypt_password(data.get('password'))  # Encrypt the password
        with sqlite3.connect('passwords.db') as conn:
            conn.execute('INSERT INTO passwords (name, password) VALUES (?, ?)', (name, password))
            return jsonify({'message': 'Password saved successfully!'}), 201

    elif request.method == 'GET':
        with sqlite3.connect('passwords.db') as conn:
            rows = conn.execute('SELECT name, password FROM passwords').fetchall()  # Fetch all passwords
            return jsonify([{'name': row[0], 'password': decrypt_password(row[1])} for row in rows])  # Decrypt and return

if __name__ == '__main__':
    app.run(debug=True)
