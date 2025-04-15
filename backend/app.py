from flask import Flask, jsonify, request
from flask_cors import CORS
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import os
import base64
import sqlite3

# Initialize Flask application and enable Cross-Origin Resource Sharing (CORS)
app = Flask(__name__)
CORS(app)

# Set the secret key for session management from environment variable
app.secret_key = os.getenv('SECRET_KEY')

# Generate a random salt for key derivation and read iterations from environment variables
KDF_SALT = os.urandom(16)  
KDF_ITERATIONS = int(os.getenv('KDF_ITERATIONS', 100000))

def init_db():
    """Initialize the SQLite database and create the passwords table if it doesn't exist."""
    with sqlite3.connect('passwords.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS passwords
            (id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            password TEXT NOT NULL,
            encryption_type TEXT NOT NULL)''')

# Call the function to initialize the database at startup
init_db()

def derive_key(password):
    """Derive a cryptographic key from the given password using PBKDF2."""
    return PBKDF2(password, KDF_SALT, 32, count=KDF_ITERATIONS)

def encrypt_password_aes(password, key):
    """Encrypt the given password using AES encryption with the provided key."""
    cipher = AES.new(key, AES.MODE_GCM)  # Create a new AES cipher object in GCM mode
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())  # Encrypt the password
    # Return the concatenated nonce, tag, and ciphertext encoded in base64
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_password_aes(encrypted, key):
    """Decrypt an AES-encrypted password using the provided key."""
    encrypted = base64.b64decode(encrypted)  # Decode from base64
    nonce, tag, ciphertext = encrypted[:16], encrypted[16:32], encrypted[32:]  # Extract nonce, tag, and ciphertext
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)  # Create a new AES cipher object with the nonce
    # Decrypt and verify the ciphertext using the tag
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

@app.route('/api/passwords', methods=['GET', 'POST'])
def manage_passwords():
    """Handle GET and POST requests for managing passwords."""
    
    if request.method == 'POST':
        # Handle password storage
        data = request.json  # Get JSON data from the request
        name = data.get('name')  # Extract name from the request data
        password = data.get('password')  # Extract password from the request data
        encryption_type = data.get('encryption_type')  # Extract encryption type

        if encryption_type == 'aes':
            key = derive_key(password)  # Derive the key from the provided password
            encrypted_password = encrypt_password_aes(password, key)  # Encrypt the password
            
            # Store the encrypted password in the database
            with sqlite3.connect('passwords.db') as conn:
                conn.execute(
                    'INSERT INTO passwords (name, password, encryption_type) VALUES (?, ?, ?)',
                    (name, encrypted_password, encryption_type)
                )
                return jsonify({'message': 'Password saved successfully!'}), 201

        else:
            return jsonify({'error': 'Invalid encryption type'}), 400  # Return error for unsupported encryption types

    elif request.method == 'GET':
        # Handle password retrieval
        with sqlite3.connect('passwords.db') as conn:
            rows = conn.execute('SELECT name, password, encryption_type FROM passwords').fetchall()  # Retrieve all stored passwords
        
        # Prepare a list to hold decrypted passwords
        decrypted_passwords = []
        for row in rows:
            name, encrypted_password, encryption_type = row
            
            if encryption_type == 'aes':
                password = "Decryption requires the correct password."  # Placeholder for decrypted password
            
            else:
                password = "Unknown encryption type"  # Handle unknown encryption types
            
            decrypted_passwords.append({'name': name, 'password': password})  # Append to results

        return jsonify(decrypted_passwords)  # Return all decrypted passwords in JSON format

if __name__ == '__main__':
    app.run(debug=True)  # Start the Flask application in debug mode
