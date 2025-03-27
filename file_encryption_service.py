from flask import Flask, request, send_from_directory, jsonify
import os
from cryptography.fernet import Fernet

app = Flask(__name__)

# Directory to store uploaded files
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Generate a key for encryption
def generate_key():
    return Fernet.generate_key()

# Encrypt the file
def encrypt_file(file_path, password):
    key = generate_key()
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    encrypted_file_path = os.path.join(UPLOAD_FOLDER, f'encrypted_{os.path.basename(file_path)}')
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)
    return encrypted_file_path, key

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    password = request.form['password']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)
    encrypted_file_path, key = encrypt_file(file_path, password)
    return jsonify({'message': 'File uploaded and encrypted', 'file_path': encrypted_file_path}), 200

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

if __name__ == '__main__':
    app.run(debug=True)
