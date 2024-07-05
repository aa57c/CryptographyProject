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
def save_string_to_postgres(input_string):
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
        if not table_exists(cur, 'my_strings'):
            # Create table if it doesn't exist
            cur.execute("""
                CREATE TABLE my_strings (
                    id SERIAL PRIMARY KEY,
                    content TEXT
                )
            """)
            print("Table 'my_strings' created successfully!")

        # Insert or update the string into the table
        cur.execute("INSERT INTO my_strings (content) VALUES (%s)", (input_string,))
        
        # Commit the transaction
        conn.commit()

        # Close cursor and connection
        cur.close()
        conn.close()
        
        print("String saved successfully to PostgreSQL!")

    except Exception as e:
        print(f"Error saving string to PostgreSQL: {e}")

# Function to retrieve the string from PostgreSQL
def retrieve_string_from_postgres():
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

        # Retrieve the string from the table
        cur.execute("SELECT content FROM my_strings ORDER BY id DESC LIMIT 1")
        retrieved_string = cur.fetchone()[0]

        # Print retrieved string
        print(f"Retrieved string from PostgreSQL: {retrieved_string}")

        # Close cursor and connection
        cur.close()
        conn.close()

        return retrieved_string

    except Exception as e:
        print(f"Error retrieving string from PostgreSQL: {e}")
        return None

# Example usage
if __name__ == "__main__":
    input_string = "Hello, PostgreSQL!"
    
    # Save string to PostgreSQL
    save_string_to_postgres(input_string)

    # Retrieve string from PostgreSQL
    retrieved_string = retrieve_string_from_postgres()

    # Display retrieved string
    if retrieved_string:
        print(f"Retrieved string: {retrieved_string}")
