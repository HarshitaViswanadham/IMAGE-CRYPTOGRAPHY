from flask import Flask, request, render_template, url_for, redirect, send_from_directory, flash
from werkzeug.utils import secure_filename
import os

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

UPLOAD_FOLDER = os.path.dirname(os.path.abspath(__file__)) + '/uploads/'
DOWNLOAD_FOLDER = os.path.dirname(os.path.abspath(__file__)) + '/downloads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__, static_url_path="/static")
DIR_PATH = os.path.dirname(os.path.realpath(__file__))
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
@app.route('/home')
def home_page():
    return render_template('home.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        text = request.form['text']
        if file.filename == '':
            return redirect(request.url)
        if text == "":
            error = 'KEY REQUIRED !'
            return render_template('encrypt.html', error=error)
        if file and allowed_file(file.filename):
            filename = "enc_"+secure_filename(file.filename)
            hash_obj = SHA256.new(text.encode('utf-8'))
            key = hash_obj.digest()
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            encrypt_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), filename, key)
            return redirect(url_for('uploaded_file', filename=filename))
    return render_template('encrypt.html')

def encryption(message, key, key_size=256):
    message = message + b"\0" * (AES.block_size - len(message) % AES.block_size)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def encrypt_file(path, filename, key):
    fo = open(app.config['UPLOAD_FOLDER']+filename, "rb")
    plaintext = fo.read()
    fo.close()
    enc = encryption(plaintext, key)
    fo = open(app.config['DOWNLOAD_FOLDER']+filename, "wb")
    fo.write(enc)
    fo.close()

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        text = request.form['text']
        if file.filename == '':
            return redirect(request.url)
        if text == "":
            error = 'KEY REQUIRED !'
            return render_template('decrypt.html', error=error)
        if file and allowed_file(file.filename):
            filename = "dec"+secure_filename(file.filename)[3:]
            hash_obj = SHA256.new(text.encode('utf-8'))
            key = hash_obj.digest()
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            decrypt_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), filename, key)
            return redirect(url_for('uploaded_file', filename=filename))
    return render_template('decrypt.html')

def decryption(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def decrypt_file(path, filename, key):
    fo = open(app.config['UPLOAD_FOLDER'] + filename, "rb")
    plaintext = fo.read()
    fo.close()
    dec = decryption(plaintext, key)
    fo = open(app.config['DOWNLOAD_FOLDER'] + filename, "wb")
    fo.write(dec)
    fo.close()

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['DOWNLOAD_FOLDER'], filename, as_attachment=True)