# We might need to specify the database for further work so I am leaving this here for quick reference if needed.
# import dj_database_url

# DATABASES = {
#     'default': dj_database_url.config(default=os.environ.get('DATABASE_URL'))
# }

from flask import Flask, render_template, request, redirect, url_for
import os
from postgres_interaction import save_string_to_postgres, retrieve_string_from_postgres
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from ecdsa import SigningKey, VerifyingKey, NIST384p
import pqcryptography as pqc
import base64
import json

# Initialize Flask application
app = Flask(__name__)

# AES Encryption
def aes_encrypt(data, key):
    # Initialize AES cipher in EAX mode
    cipher = AES.new(key, AES.MODE_EAX)
    # Encrypt the data and get the ciphertext and tag
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # Encode the nonce, tag, and ciphertext in base64 for easy storage
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

# AES Decryption
def aes_decrypt(encrypted_data, key):
    # Decode the base64 encoded data
    data = base64.b64decode(encrypted_data)
    # Extract nonce, tag, and ciphertext
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    # Initialize AES cipher in EAX mode with the extracted nonce
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    # Decrypt and verify the ciphertext
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# PQC Encrypt (using default Kyber1024)
def pqc_encrypt(public_key, data):
    # Encrypt the data using the public key
    return pqc.encryption.encrypt(public_key, data.encode('utf-8'))

# PQC Decrypt (using default Kyber1024)
def pqc_decrypt(private_key, encrypted_data):
    # Decrypt the data using the private key
    return pqc.encryption.decrypt(private_key, encrypted_data).decode('utf-8')

# ECC Sign
def ecc_sign(data):
    # Generate ECC signing key
    sk = SigningKey.generate(curve=NIST384p)
    # Get the corresponding verifying key
    vk = sk.verifying_key
    # Sign the data
    signature = sk.sign(data)
    return signature, vk

# ECC Verify
def ecc_verify(signature, data, vk):
    # Verify the data with the provided signature and verifying key
    return vk.verify(signature, data)

# Route to save text to the database
@app.route('/', methods=['GET', 'POST'])
def save_text():
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

        # Prepare data for storage
        data_to_store = {
            'aes_encrypted_data': aes_encrypted_text,
            'pqc_encrypted_key': base64.b64encode(pqc_encrypted_aes_key).decode('utf-8'),
            'ecc_signature': base64.b64encode(ecc_signature).decode('utf-8'),
            'ecc_verifying_key': base64.b64encode(ecc_verifying_key.to_string()).decode('utf-8'),
            'pqc_private_key': base64.b64encode(private_key).decode('utf-8')
        }
        # Save encrypted data to the database
        save_string_to_postgres(json.dumps(data_to_store))
        return redirect(url_for('retrieve_text'))
    return render_template('message_save.html')

# Route to retrieve and display text from the database
@app.route('/retrieve', methods=['GET'])
def retrieve_text():
    stored_data = retrieve_string_from_postgres()
    data = json.loads(stored_data)

    # Decode data from storage
    aes_encrypted_data = data['aes_encrypted_data']
    pqc_encrypted_key = base64.b64decode(data['pqc_encrypted_key'])
    ecc_signature = base64.b64decode(data['ecc_signature'])
    ecc_verifying_key = VerifyingKey.from_string(base64.b64decode(data['ecc_verifying_key']), curve=NIST384p)
    pqc_private_key = base64.b64decode(data['pqc_private_key'])

    try:
        # Verify the signature using ECC
        ecc_is_verified = ecc_verify(ecc_signature, aes_encrypted_data.encode('utf-8'), ecc_verifying_key)
        if ecc_is_verified:
            # Decrypt AES key using PQC
            decrypted_aes_key = base64.b64decode(pqc_decrypt(pqc_private_key, pqc_encrypted_key))
            
            # Decrypt text using AES
            decrypted_text = aes_decrypt(aes_encrypted_data, decrypted_aes_key)
            
            # Render the message view template with the decrypted text
            return render_template('message_view.html', text=decrypted_text, verified=True)
        else:
            # Render the message view template indicating verification failure
            return render_template('message_view.html', text="Verification failed. Data integrity could not be confirmed.", verified=False)
    except Exception as e:
        # Render the message view template indicating an error
        return render_template('message_view.html', text=f"An error occurred: {str(e)}", verified=False)

# Run the Flask application
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5600))
    app.run(debug=True, host='0.0.0.0', port=port)
