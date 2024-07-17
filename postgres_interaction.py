import psycopg2

# Database connection parameters
dbname = "mydatabase"
user = "postgres"
password = "password"
host = "db"
port = "5432"

# Function to check if table exists
def table_exists(cur, table_name):
    cur.execute("""
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_name = %s
        )
    """, (table_name,))
    return cur.fetchone()[0]

# Function to create or update table and save patient data to PostgreSQL
def save_patient_data_to_postgres(patient_name, aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key):
    try:
        # Connect to PostgreSQL database
        conn = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port
        )

        # Open a cursor to perform database operations
        cur = conn.cursor()

        # Check if table exists
        if not table_exists(cur, 'patient_data'):
            # Create table if it doesn't exist
            cur.execute("""
                CREATE TABLE patient_data (
                    id SERIAL PRIMARY KEY,
                    patient_name TEXT,
                    aes_encrypted_data TEXT,
                    pqc_encrypted_key TEXT,
                    ecc_signature TEXT,
                    ecc_verifying_key TEXT,
                    pqc_private_key TEXT
                )
            """)
            print("Table 'patient_data' created successfully!")

        # Insert the patient data into the table
        cur.execute("""
            INSERT INTO patient_data (patient_name, aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (patient_name, aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key))
        
        # Commit the transaction
        conn.commit()

        # Close cursor and connection
        cur.close()
        conn.close()
        
        print("Patient data saved successfully to PostgreSQL!")

    except Exception as e:
        print(f"Error saving patient data to PostgreSQL: {e}")

# Function to retrieve the latest patient entry from PostgreSQL
def retrieve_latest_patient_from_postgres():
    try:
        # Connect to PostgreSQL database
        conn = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port
        )

        # Open a cursor to perform database operations
        cur = conn.cursor()

        # Retrieve the latest patient entry from the table
        cur.execute("""
            SELECT id, patient_name, aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key
            FROM patient_data ORDER BY id DESC LIMIT 1
        """)
        result = cur.fetchone()

        # Close cursor and connection
        cur.close()
        conn.close()

        return result

    except Exception as e:
        print(f"Error retrieving patient data from PostgreSQL: {e}")
        return None

# Function to retrieve all patient entries from PostgreSQL
def retrieve_all_patients_from_postgres():
    try:
        conn = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port
        )
        cur = conn.cursor()
        cur.execute("""
            SELECT id, patient_name, aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key
            FROM patient_data ORDER BY id
        """)
        results = cur.fetchall()
        cur.close()
        conn.close()
        return results
    except Exception as e:
        print(f"Error retrieving all patient data from PostgreSQL: {e}")
        return []

# Function to search for patient records in the database by ID
def search_patient_by_id_in_postgres(search_id):
    try:
        # Connect to PostgreSQL database
        conn = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port
        )

        # Open a cursor to perform database operations
        cur = conn.cursor()

        # Perform the search query by ID
        cur.execute("""
            SELECT id, patient_name, aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key
            FROM patient_data WHERE id = %s
        """, (search_id,))
        result = cur.fetchone()

        # Close cursor and connection
        cur.close()
        conn.close()

        return result

    except Exception as e:
        print(f"Error searching patient data by ID in PostgreSQL: {e}")
        return None

# Function to delete all patient entries from PostgreSQL
def delete_all_entries_from_postgres():
    try:
        conn = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port
        )
        cur = conn.cursor()
        cur.execute("DELETE FROM patient_data")
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error deleting all patient entries from PostgreSQL: {e}")
# Function to search for patient records in the database by ID or name
def search_patient_by_id_or_name_in_postgres(patient_id=None, patient_name=None):
    try:
        # Connect to PostgreSQL database
        conn = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port
        )

        # Open a cursor to perform database operations
        cur = conn.cursor()

        # Perform the search query by ID or name
        if patient_id:
            cur.execute("""
                SELECT id, patient_name, aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key
                FROM patient_data WHERE id = %s
            """, (patient_id,))
        elif patient_name:
            cur.execute("""
                SELECT id, patient_name, aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key
                FROM patient_data WHERE patient_name ILIKE %s
            """, (f'%{patient_name}%',))
        else:
            return []

        results = cur.fetchall()

        # Close cursor and connection
        cur.close()
        conn.close()

        return results

    except Exception as e:
        print(f"Error searching patient data by ID or name in PostgreSQL: {e}")
        return []

# Function to delete entries by ID or name from PostgreSQL
def delete_entry_by_id_or_name_from_postgres(entry_id=None, entry_name=None):
    try:
        conn = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port
        )
        cur = conn.cursor()

        if entry_id:
            cur.execute("DELETE FROM patient_data WHERE id = %s", (entry_id,))
        elif entry_name:
            cur.execute("DELETE FROM patient_data WHERE patient_name ILIKE %s", (f'%{entry_name}%',))
        else:
            return

        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error deleting entries from PostgreSQL: {e}")

