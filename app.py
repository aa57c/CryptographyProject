# We might need to specify the database for further work so I am leaving this here for quick reference if needed.
# import dj_database_url

# DATABASES = {
#     'default': dj_database_url.config(default=os.environ.get('DATABASE_URL'))
# }

from flask import Flask, render_template, request, redirect, url_for, flash
import os
from postgres_interaction import delete_all_entries_from_postgres, delete_entry_by_id_or_name_from_postgres, save_patient_data_to_postgres, retrieve_latest_patient_from_postgres, search_patient_by_id_in_postgres, retrieve_all_patients_from_postgres, search_patient_by_id_or_name_in_postgres
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from ecdsa import SigningKey, VerifyingKey, NIST384p
import pqcryptography as pqc
import base64

# Initialize Flask application
app = Flask(__name__)
# app = Flask(__name__, static_folder='app/static')
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

# Route to add patient and encrypt data
@app.route('/add_patient', methods=['GET', 'POST'])
def add_patient():
    if request.method == 'POST':
        patient_name = request.form['name']
        patient_data = request.form['data']

        # Generate a random AES key
        aes_key = get_random_bytes(32)

        # Encrypt the patient data using AES
        aes_encrypted_data = aes_encrypt(patient_data.encode('utf-8'), aes_key)

        # Generate PQC key pair (using default Kyber1024)
        public_key, private_key = pqc.encryption.generate_keypair()

        # Encrypt the AES key using PQC
        pqc_encrypted_aes_key = pqc_encrypt(public_key, base64.b64encode(aes_key).decode('utf-8'))

        # Sign the AES encrypted data using ECC
        ecc_signature, ecc_verifying_key = ecc_sign(aes_encrypted_data.encode('utf-8'))

        # Save patient data to the database
        save_patient_data_to_postgres(
            patient_name,
            aes_encrypted_data,
            base64.b64encode(pqc_encrypted_aes_key).decode('utf-8'),
            base64.b64encode(ecc_signature).decode('utf-8'),
            base64.b64encode(ecc_verifying_key.to_string()).decode('utf-8'),
            base64.b64encode(private_key).decode('utf-8')
        )

        # Flash a success message
        flash('Patient data has been successfully encrypted and saved!')

        return redirect(url_for('home'))
    return render_template('add_patient.html')

# Route to retrieve and verify patient data
@app.route('/verify_patient', methods=['GET', 'POST'])
def verify_patient():
    if request.method == 'POST':
        patient_id = request.form.get('patient_id')

        if patient_id:
            stored_data = search_patient_by_id_in_postgres(patient_id)
        else:
            stored_data = retrieve_latest_patient_from_postgres()
        
        if not stored_data:
            flash("No data found with the provided ID.")
            return redirect(url_for('home'))

        patient_id, patient_name, aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key = stored_data

        # Decode data from storage
        ecc_signature = base64.b64decode(ecc_signature)
        ecc_verifying_key = VerifyingKey.from_string(base64.b64decode(ecc_verifying_key), curve=NIST384p)

        try:
            # Verify the signature using ECC
            if ecc_verify(ecc_signature, aes_encrypted_data.encode('utf-8'), ecc_verifying_key):
                flash('Signature verified. You can now decrypt the data.')
                return render_template('decrypt_patient.html', verified=True, patient_id=patient_id, patient_name=patient_name, aes_encrypted_data=aes_encrypted_data)
            else:
                flash('Signature verification failed. Data integrity could not be confirmed.')
                return redirect(url_for('home'))
        except Exception as e:
            flash(f"An error occurred: {str(e)}")
            return redirect(url_for('home'))
    return render_template('verify_patient.html', patient_name=patient_name, aes_encrypted_data=aes_encrypted_data)

# Route to retrieve and decrypt patient data from the database
@app.route('/decrypt_patient', methods=['GET', 'POST'])
def decrypt_patient():
    if request.method == 'POST':
        if 'verify' in request.form:
            return verify_patient()

        if 'decrypt' in request.form:
            patient_id = request.form.get('patient_id')
            if patient_id:
                stored_data = search_patient_by_id_in_postgres(patient_id)
            else:
                stored_data = retrieve_latest_patient_from_postgres()

            if not stored_data:
                flash("No data found with the provided ID.")
                return render_template('decrypt_patient.html')

            patient_id, patient_name, aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key = stored_data

            # Decode data from storage
            pqc_encrypted_key = base64.b64decode(pqc_encrypted_key)
            pqc_private_key = base64.b64decode(pqc_private_key)

            try:
                # Decrypt AES key using PQC
                decrypted_aes_key = base64.b64decode(pqc_decrypt(pqc_private_key, pqc_encrypted_key))

                # Decrypt text using AES
                decrypted_text = aes_decrypt(aes_encrypted_data, decrypted_aes_key)

                # Flash a success message
                flash('Patient data has been successfully decrypted!')
                
                return render_template('decrypt_patient.html', patient_name=patient_name, data=decrypted_text, aes_encrypted_data=aes_encrypted_data, verified=True)
            except Exception as e:
                flash(f"An error occurred: {str(e)}")
                return render_template('decrypt_patient.html')
    return render_template('decrypt_patient.html')

# Route to display the database contents
@app.route('/database', methods=['GET'])
def view_database():
    # Retrieve all records from the database
    all_data = retrieve_all_patients_from_postgres()
    # Pass the data to the template for rendering
    return render_template('database.html', data=all_data)

# Route to search patient by ID or name
@app.route('/search_patient', methods=['GET', 'POST'])
def search_patient():
    if request.method == 'POST':
        patient_id = request.form.get('patient_id')
        patient_name = request.form.get('patient_name')
        search_results = search_patient_by_id_or_name_in_postgres(patient_id, patient_name)
        return render_template('search_patient_results.html', patient_id=patient_id, patient_name=patient_name, results=search_results)
    return render_template('search_patient.html')

# Route to delete entry by ID or name
@app.route('/delete_entry', methods=['POST'])
def delete_entry():
    entry_id = request.form.get('entry_id')
    entry_name = request.form.get('entry_name')
    try:
        delete_entry_by_id_or_name_from_postgres(entry_id, entry_name)
        flash('Entry has been successfully deleted.')
    except Exception as e:
        flash(f"An error occurred while deleting the entry: {str(e)}")
    return redirect(url_for('home'))

# Route to delete all entries in the database
@app.route('/delete_all', methods=['POST'])
def delete_all():
    try:
        delete_all_entries_from_postgres()
        flash('All entries have been successfully deleted.')
    except Exception as e:
        flash(f"An error occurred while deleting entries: {str(e)}")
    return redirect(url_for('home'))

# Run the Flask application
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5600))
    app.run(debug=True, host='0.0.0.0', port=port)
