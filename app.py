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

# Initialize Flask application
app = Flask(__name__)

# Database connection parameters
# dbname = "mydatabase"
# user = "postgres"
# password = "password"
# host = "db"
# port = "5432"

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
