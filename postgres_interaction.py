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

# Function to create or update table and save a string to PostgreSQL
def save_data_to_postgres(aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key):
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
        if not table_exists(cur, 'encrypted_data'):
            # Create table if it doesn't exist
            cur.execute("""
                CREATE TABLE encrypted_data (
                    id SERIAL PRIMARY KEY,
                    aes_encrypted_data TEXT,
                    pqc_encrypted_key TEXT,
                    ecc_signature TEXT,
                    ecc_verifying_key TEXT,
                    pqc_private_key TEXT
                )
            """)
            print("Table 'encrypted_data' created successfully!")

        # Insert the data into the table
        cur.execute("""
            INSERT INTO encrypted_data (aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key)
            VALUES (%s, %s, %s, %s, %s)
        """, (aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key))
        
        # Commit the transaction
        conn.commit()

        # Close cursor and connection
        cur.close()
        conn.close()
        
        print("Data saved successfully to PostgreSQL!")

    except Exception as e:
        print(f"Error saving data to PostgreSQL: {e}")

# Function to retrieve the latest entry from PostgreSQL
def retrieve_latest_entry_from_postgres():
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

        # Retrieve the latest entry from the table
        cur.execute("""
            SELECT aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key
            FROM encrypted_data ORDER BY id DESC LIMIT 1
        """)
        result = cur.fetchone()

        # Close cursor and connection
        cur.close()
        conn.close()

        return result

    except Exception as e:
        print(f"Error retrieving data from PostgreSQL: {e}")
        return None

# Function to retrieve all entries from PostgreSQL
def retrieve_all_entries_from_postgres():
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
            SELECT id, aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key
            FROM encrypted_data ORDER BY id
        """)
        results = cur.fetchall()
        cur.close()
        conn.close()
        return results
    except Exception as e:
        print(f"Error retrieving all data from PostgreSQL: {e}")
        return []

# Function to search for records in the database by ID
def search_by_id_in_postgres(search_id):
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
            SELECT id, aes_encrypted_data, pqc_encrypted_key, ecc_signature, ecc_verifying_key, pqc_private_key
            FROM encrypted_data WHERE id = %s
        """, (search_id,))
        result = cur.fetchone()

        # Close cursor and connection
        cur.close()
        conn.close()

        return result

    except Exception as e:
        print(f"Error searching by ID in PostgreSQL: {e}")
        return None
