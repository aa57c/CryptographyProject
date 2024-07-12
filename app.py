# We might need to specify the database for further work so I am leaving this here for quick reference if needed.
# import dj_database_url

# DATABASES = {
#     'default': dj_database_url.config(default=os.environ.get('DATABASE_URL'))
# }

from flask import Flask, render_template, request, redirect, url_for, flash
import os
from postgres_interaction import save_data_to_postgres, retrieve_latest_entry_from_postgres, search_by_id_in_postgres, retrieve_all_entries_from_postgres
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from ecdsa import SigningKey, VerifyingKey, NIST384p
import pqcryptography as pqc
import base64

# Initialize Flask application
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secret key for session management

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

# PQC Encrypt (using default Kyber1024)
def pqc_encrypt(public_key, data):
    return pqc.encryption.encrypt(public_key, data.encode('utf-8'))

# PQC Decrypt (using default Kyber1024)
def pqc_decrypt(private_key, encrypted_data):
    return pqc.encryption.decrypt(private_key, encrypted_data).decode('utf-8')

# ECC Sign
def ecc_sign(data):
    sk = SigningKey.generate(curve=NIST384p)
    vk = sk.verifying_key
    signature = sk.sign(data)
    return signature, vk

# ECC Verify
def ecc_verify(signature, data, vk):
    return vk.verify(signature, data)

# Home Route
@app.route('/')
def home():
    return render_template('home.html')

# Route to encrypt text and save to the database
@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt_text():
    if request.method == 'POST':
        text = request.form['text']

        # Generate a random AES key
        aes_key = get_random_bytes(32)

        # Encrypt the text using AES
        aes_encrypted_text = aes_encrypt(text.encode('utf-8'), aes_key)

        # Generate PQC key pair (using default Kyber1024)
        public_key, private_key = pqc.encryption.generate_keypair()

        # Encrypt the AES key using PQC
        pqc_encrypted_aes_key = pqc_encrypt(public_key, base64.b64encode(aes_key).decode('utf-8'))

        # Sign the AES encrypted data using ECC
        ecc_signature, ecc_verifying_key = ecc_sign(aes_encrypted_text.encode('utf-8'))

        # Save data to the database
        save_data_to_postgres(
            aes_encrypted_text,
            base64.b64encode(pqc_encrypted_aes_key).decode('utf-8'),
            base64.b64encode(ecc_signature).decode('utf-8'),
            base64.b64encode(ecc_verifying_key.to_string()).decode('utf-8'),
            base64.b64encode(private_key).decode('utf-8')
        )

        # Flash a success message
        flash('Data has been successfully encrypted and saved!')

        return redirect(url_for('home'))
    return render_template('encrypt.html')

# Route to retrieve and verify the ECC signature
@app.route('/verify', methods=['GET', 'POST'])
def verify_signature():
    if request.method == 'POST':
        data_id = request.form.get('data_id')
        if data_id:
            stored_data = search_by_id_in_postgres(data_id)
        else:
            stored_data = retrieve_latest_entry_from_postgres()

        if not stored_data:
            flash("No data found with the provided ID.")
            return redirect(url_for('decrypt_text'))

        aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key = stored_data

        # Decode data from storage
        ecc_signature = base64.b64decode(ecc_signature)
        ecc_verifying_key = VerifyingKey.from_string(base64.b64decode(ecc_verifying_key), curve=NIST384p)

        try:
            # Verify the signature using ECC
            if ecc_verify(ecc_signature, aes_encrypted_data.encode('utf-8'), ecc_verifying_key):
                flash('Signature verified. You can now decrypt the data.')
                return render_template('decrypt.html', verified=True, data_id=data_id)
            else:
                flash('Signature verification failed. Data integrity could not be confirmed.')
                return redirect(url_for('decrypt_text'))
        except Exception as e:
            flash(f"An error occurred: {str(e)}")
            return redirect(url_for('decrypt_text'))
    return render_template('verify.html')

# Route to retrieve and decrypt text from the database
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt_text():
    if request.method == 'POST':
        if 'verify' in request.form:
            return verify_signature()

        if 'decrypt' in request.form:
            data_id = request.form.get('data_id')
            if data_id:
                stored_data = search_by_id_in_postgres(data_id)
            else:
                stored_data = retrieve_latest_entry_from_postgres()

            if not stored_data:
                flash("No data found with the provided ID.")
                return render_template('decrypt.html')

            aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key = stored_data

            # Decode data from storage
            pqc_encrypted_key = base64.b64decode(pqc_encrypted_key)
            pqc_private_key = base64.b64decode(pqc_private_key)

            try:
                # Decrypt AES key using PQC
                decrypted_aes_key = base64.b64decode(pqc_decrypt(pqc_private_key, pqc_encrypted_key))

                # Decrypt text using AES
                decrypted_text = aes_decrypt(aes_encrypted_data, decrypted_aes_key)

                # Flash a success message
                flash('Data has been successfully decrypted!')
                
                return render_template('decrypt.html', text=decrypted_text, verified=True)
            except Exception as e:
                flash(f"An error occurred: {str(e)}")
                return render_template('decrypt.html')
    return render_template('decrypt.html')

# Route to display the database contents
@app.route('/database', methods=['GET'])
def view_database():
    # Retrieve all records from the database
    all_data = retrieve_all_entries_from_postgres()
    # Pass the data to the template for rendering
    return render_template('database.html', data=all_data)

# Route to search the database by ID
@app.route('/search_id', methods=['GET', 'POST'])
def search_by_id():
    if request.method == 'POST':
        search_id = request.form['search_id']
        search_result = search_by_id_in_postgres(search_id)
        return render_template('search_id_results.html', search_id=search_id, result=search_result)
    return render_template('search_id.html')

# Run the Flask application
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5600))
    app.run(debug=True, host='0.0.0.0', port=port)
