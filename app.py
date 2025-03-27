from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import logging

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ENCRYPTED_FOLDER'] = 'encrypted'
app.config['LOG_FILE'] = 'transfer.log'

# Ensure upload and encrypted directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['ENCRYPTED_FOLDER'], exist_ok=True)

# Setup logging
logging.basicConfig(filename=app.config['LOG_FILE'], level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def encrypt_file(file_path, password):
    """Encrypt a file using AES-256."""
    key = hashlib.sha256(password.encode()).digest()
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Pad the plaintext to be a multiple of AES block size
    padding_length = AES.block_size - len(plaintext) % AES.block_size
    plaintext += bytes([padding_length] * padding_length)

    ciphertext = cipher.encrypt(plaintext)

    encrypted_file_path = os.path.join(app.config['ENCRYPTED_FOLDER'], os.path.basename(file_path) + '.enc')
    with open(encrypted_file_path, 'wb') as f:
        f.write(iv + ciphertext)

    return encrypted_file_path

def decrypt_file(file_path, password):
    """Decrypt a file using AES-256."""
    with open(file_path, 'rb') as f:
        iv = f.read(AES.block_size)
        ciphertext = f.read()

    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = cipher.decrypt(ciphertext)

    # Remove padding
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]

    decrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(file_path)[:-4])  # Remove .enc extension
    with open(decrypted_file_path, 'wb') as f:
        f.write(plaintext)

    return decrypted_file_path

def calculate_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(request.url)

        file = request.files['file']
        password = request.form.get('password')

        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)

        if not password:
            flash('Password is required')
            return redirect(request.url)

        # Save the uploaded file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # Encrypt the file
        encrypted_file_path = encrypt_file(file_path, password)

        # Calculate file hash
        file_hash = calculate_hash(file_path)

        # Log the transfer
        logging.info(f"File {file.filename} encrypted successfully. Hash: {file_hash}")

        return render_template('result.html', 
                              original_file=file.filename, 
                              encrypted_file=os.path.basename(encrypted_file_path), 
                              file_hash=file_hash)

    # Get recent transfers from log file
    recent_transfers = []
    if os.path.exists(app.config['LOG_FILE']):
        with open(app.config['LOG_FILE'], 'r') as log_file:
            lines = log_file.readlines()
            for line in lines[-5:]:  # Get last 5 transfers
                if 'encrypted successfully' in line:
                    parts = line.split(' - ')
                    timestamp = parts[0]
                    filename = line.split('File ')[1].split(' encrypted')[0]
                    file_hash = line.split('Hash: ')[1].strip()
                    recent_transfers.append({
                        'filename': filename,
                        'timestamp': timestamp,
                        'hash': file_hash
                    })

    return render_template('index.html', recent_transfers=recent_transfers)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_file = request.form.get('encrypted_file')
    password = request.form.get('password')

    if not encrypted_file or not password:
        flash('Encrypted file and password are required')
        return redirect(url_for('index'))

    encrypted_file_path = os.path.join(app.config['ENCRYPTED_FOLDER'], encrypted_file)
    if not os.path.exists(encrypted_file_path):
        flash('Encrypted file not found')
        return redirect(url_for('index'))

    try:
        decrypted_file_path = decrypt_file(encrypted_file_path, password)
        logging.info(f"File {encrypted_file} decrypted successfully.")
        return render_template('result.html', 
                              original_file=os.path.basename(decrypted_file_path), 
                              encrypted_file=encrypted_file, 
                              file_hash=calculate_hash(decrypted_file_path),
                              decrypted=True)
    except Exception as e:
        flash('Decryption failed. Incorrect password or corrupted file.')
        logging.error(f"Decryption failed for {encrypted_file}: {str(e)}")
        return redirect(url_for('index'))

@app.route('/download/<filename>')
def download(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        flash('File not found')
        return redirect(url_for('index'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
