# We might need to specify database for futher work so I am leaving this here for quick reference
# if needed.
# import dj_database_url

# DATABASES = {
#     'default': dj_database_url.config(default=os.environ.get('DATABASE_URL'))
# }

from flask import Flask, render_template, request, redirect, url_for
import os
import psycopg2
from postgres_interaction import save_string_to_postgres, retrieve_string_from_postgres
from Crypto.Cipher import AES
from ecdsa import SigningKey, SECP256k1
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from pqcrypto.sign import sphincs_haraka_128f_robust
import base64




# Initialize Flask application
app = Flask(__name__)

# Database connection parameters
# dbname = "mydatabase"
# user = "postgres"
# password = "password"
# host = "db"
# port = "5432"


# This commented out code does not work in docker when i try to run it.

# AES encryption/decryption
def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def aes_decrypt(key, data):
    raw_data = base64.b64decode(data)
    nonce = raw_data[:16]
    ciphertext = raw_data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext).decode('utf-8')
    return plaintext

# ECC encryption/decryption
def ecc_sign(data):
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key
    signature = sk.sign(data.encode('utf-8'))
    return vk.to_pem().decode('utf-8'), base64.b64encode(signature).decode('utf-8')

def ecc_verify(public_key, signature, data):
    vk = SigningKey.from_pem(public_key).verifying_key
    return vk.verify(base64.b64decode(signature), data.encode('utf-8'))

# Post-Quantum cryptography using SPHINCS+

def pq_sign(data):
    sk = sphincs_haraka_128f_robust.generate_keypair()
    signature = sphincs_haraka_128f_robust.sign(sk, data.encode('utf-8'))
    pk = sk.get_public_key()
    return base64.b64encode(pk).decode('utf-8'), base64.b64encode(signature).decode('utf-8')


def pq_verify(public_key, signature, data):
    pk = base64.b64decode(public_key)
    sig = base64.b64decode(signature)
    return sphincs_haraka_128f_robust.verify(pk, data.encode('utf-8'), sig)






# Route to save text to the database
@app.route('/', methods=['GET', 'POST'])
def save_text():
    if request.method == 'POST':
        text = request.form['text']
        save_string_to_postgres(text)
        return redirect(url_for('retrieve_text'))
    return render_template('message_save.html')

# Route to retrieve and display text from the database
@app.route('/retrieve', methods=['GET'])
def retrieve_text():
    text = retrieve_string_from_postgres()
    return render_template('message_view.html', text=text)

# Run the Flask application
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5600))
    app.run(debug=True, host='0.0.0.0', port=port)
