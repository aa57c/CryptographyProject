# We might need to specify database for futher work so I am leaving this here for quick reference
# if needed.
# import dj_database_url

# DATABASES = {
#     'default': dj_database_url.config(default=os.environ.get('DATABASE_URL'))
# }

from flask import Flask, render_template, request, redirect, url_for
import os
from postgres_interaction import save_string_to_postgres, retrieve_string_from_postgres
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
# from ecdsa import SigningKey, VerifyingKey, NIST384p
from pqcrypto.kem import kyber512
import base64
import json

# Initialize Flask application
app = Flask(__name__)

# Database connection parameters
# dbname = "mydatabase"
# user = "postgres"
# password = "password"
# host = "db"
# port = "5432"

# AES Encryption

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

# AES Decryption
def aes_decrypt(encrypted_data, key):
    data = base64.b64decode(encrypted_data)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# PQC Key Encryption
def pqc_encrypt_key(aes_key):
    pk, sk = kyber512.generate_keypair()
    encrypted_key = kyber512.encrypt(pk, aes_key)
    return base64.b64encode(encrypted_key).decode('utf-8'), sk

# PQC Key Decryption
def pqc_decrypt_key(encrypted_key, sk):
    encrypted_key = base64.b64decode(encrypted_key)
    aes_key = kyber512.decrypt(sk, encrypted_key)
    return aes_key

'''
# ECC Key Generation
def generate_ecc_key():
    # Generate ECC key
    # sk = SigningKey.generate(curve=NIST384p)
    # vk = sk.verifying_key
    # return sk, vk

# ECC Signing
def ecc_sign(data, sk):
    # ECC signing
    # signature = sk.sign(data.encode('utf-8'))
    # return base64.b64encode(signature).decode('utf-8')

# ECC Verification
def ecc_verify(data, signature, vk):
    # verification
    #try:
    #    vk.verify(base64.b64decode(signature), data.encode('utf-8'))
    #    return True
    #except:
    #    return False

# Example Post-Quantum Encryption function
def pqc_encrypt(data):
    # Implement the specific post-quantum encryption here
    return data

# Example Post-Quantum Decryption function
def pqc_decrypt(data):
    # Implement the specific post-quantum decryption here
    return data
'''

# Route to save text to the database
@app.route('/', methods=['GET', 'POST'])
def save_text():
    if request.method == 'POST':
        text = request.form['text']

        # AES encryption
        aes_key = get_random_bytes(32) # AES-256
        aes_encrypted = aes_encrypt(text.encode('utf-8'), aes_key)

        # PQC encryption of AES key
        pqc_encrypted_key, pqc_sk = pqc_encrypt_key(aes_key)

        # ECC key generation and signing
        # sk, vk = generate_ecc_key()
        # ecc_signature = ecc_sign(text, sk)
        # PQC encryption (example)
        # pqc_encrypted = pqc_encrypt(text)

        # Prepare data to be saved
        text_data = {
            'aes_encrypted' : aes_encrypted,
            'pqc_encrypted_key': pqc_encrypted_key,
            'pqc_sk': base64.b64encode(pqc_sk).decode('utf-8')
            #'ecc_signature': ecc_signature,
            #'ecc_verifying_key': vk.to_string().hex(),
            #'pqc_encrypted': pqc_encrypted
        }
        save_string_to_postgres(json.dumps(text_data))
        
        return redirect(url_for('retrieve_text'))
    return render_template('message_save.html')

# Route to retrieve and display text from the database
@app.route('/retrieve', methods=['GET'])
def retrieve_text():
    text_data_json = retrieve_string_from_postgres()
    text_data = json.loads(text_data_json)

    aes_encrypted = text_data['aes_encrypted']
    pqc_encrypted_key = text_data['pqc_encrypted_key']
    pqc_sk = base64.b64decode(text_data['pqc_sk'])
    # ecc_signature = text_data['ecc_signature']
    # ecc_verifying_key_hex = text_data['ecc_verifying_key']
    # pqc_encrypted = text_data['pqc_encrypted']

    # PQC decryption of AES key
    aes_key = pqc_decrypt_key(pqc_encrypted_key, pqc_sk)

    # AES decryption
    aes_decrypted = aes_decrypt(aes_encrypted, aes_key)

    # ECC verification
    # vk = VerifyingKey.from_string(bytes.fromhex(ecc_verifying_key_hex), curve=NIST384p)
    # ecc_verified = ecc_verify(aes_decrypted, ecc_signature, vk)
    
    # PQC decryption (example)
    # pqc_decrypted = pqc_decrypt(pqc_encrypted)

    return render_template('message_view.html', text=aes_decrypted)

# Run the Flask application
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5600))
    app.run(debug=True, host='0.0.0.0', port=port)
