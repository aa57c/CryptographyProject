# 🔐 Cryptography Project

This is a secure web application built with Flask for encrypting and managing sensitive patient data. It allows healthcare providers or researchers to store encrypted records in a PostgreSQL database and decrypt them when needed. The application is Docker-ready for containerized deployment and includes a clean web interface.

Deployment is at this domain using Elastic Beanstalk: http://crypt-app-2-dev.us-east-1.elasticbeanstalk.com/

---

## 📦 Features

- ✅ Encrypt patient data before saving it to the database
- ✅ Decrypt data only when necessary using a secure key
- ✅ PostgreSQL integration for persistent storage
- ✅ Easy-to-use web interface built with HTML/CSS (Jinja2 templating)
- ✅ Docker support for local or cloud deployment (e.g., AWS Elastic Beanstalk)

---

## 🛠️ Technologies Used

- **Python** (Flask)
- **Cryptography** library for encryption/decryption
- **PostgreSQL** for database management
- **Docker** and **Dockerrun.aws.json** for deployment
- **HTML / CSS** for frontend

---

## 📁 Project Structure

CryptographyProject-main/ ├── app.py # Main Flask app with route definitions ├── postgres_interaction.py # Database connection and SQL queries ├── requirements.txt # Python dependencies ├── Dockerfile # Docker image configuration ├── Dockerrun.aws.json # AWS deployment configuration ├── templates/ # HTML templates │ ├── add_patient.html # Page to input patient info │ ├── decrypt_patient.html # Page to decrypt patient data │ └── database.html # View encrypted records ├── static/ │ └── style.css # Web app styling └── README.md # Project documentation


---

## 🔧 Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/CryptographyProject.git
cd CryptographyProject-main
```
### 2. Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```
### 3. Install Dependencies
```bash
pip install -r requirements.txt
```
### 4. Configure PostgreSQL
- Ensure PostgreSQL is installed and running.
- Create a database and table matching your schema.
- Update the connection string in postgres_interaction.py with your PostgreSQL credentials (host, dbname, user, password, port).
### 5. Run the Flask Application
```bash
python app.py
```
Visit the app in your browser at:
📍 http://127.0.0.1:5600/

#### Docker Deployment
To build and run the app using Docker:
### 1. Build the image
```bash
docker build -t cryptography-app .
```
### 2. Run the container
```bash
docker run -p 5600:5600 cryptography-app
```
Then go to http://localhost:5600/ in your browser.

#### AWS Deployment

If you're deploying this app on AWS Elastic Beanstalk:
- Zip the project files.
- Use the provided Dockerrun.aws.json to define your Docker container settings.
- Upload the zipped bundle to AWS Elastic Beanstalk (using Single Container Docker environment).

Make sure your PostgreSQL instance is accessible to the application (RDS or similar).

#### Encryption Notes
- The app uses the cryptography.fernet module for symmetric encryption.
- The key used for encryption should be securely managed (e.g., via environment variables or AWS Secrets Manager).
- Never hard-code secret keys in the source code for production use.

#### Author
Developed by: Ashna Ali
Collaborated with: JRossetto17 (His github to the local environment setup is found here: https://github.com/JRossetto17/CryptographyProject)
