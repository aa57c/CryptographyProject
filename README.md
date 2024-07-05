# About

This project seeks to apply Cryptographic Algorithms to send a secure encrypted message and  successfully decrypt it. 

The application is a Phyton application running on Flask inside of a docker container. For simplicity of the application we are using a posgreSQL database to store data.

## Requirements
-Docker Desktop or Docker in terminal

-Git Hub account set up
## Installation
Application is fully dockerized for installation. Follow these steps to get it running. After installing docker on your computer and setting up git hub. First clone the repo with the following command:

```bash
git clone https://github.com/JRossetto17/CryptographyProject.git
```
Note: we want to clone from dev branch to make updates


After the clone is complete we will first build the docker image with:
```bash
docker image build -t 5533_project .
```

once the image is build we will use docker compose to run the application, use either one of the following command to run the app:

- For Mac:
```bash
docker-compose up 
```
- For Windows:
```bash
docker compose up 
```
All set the application should start running. Now you can visit local host + port to view the site: 
```bash
localhost:5600
```
Tip - Some changes like config and Docker changes will require the app to rebuild, to do this you can use the following command for the app to rebuild and apply updates.
- For Mac:
```bash
docker-compose up —build
```
- For Windows:
```bash
docker compose up —build
```

## Usage

```python
# import necessary dependencies or files
from flask import Flask

#Defines routes
@app.route('/')
   #renders templates routes depending on route
   return render_template("template_name.html")

#Initializeds Flask
if __name__ == '__main__':
    app.run(debug=True)
```

## Contributing

Contributing is limited to team members. Request to be added to the team to propose changes. Comments and Feedback are welcome!

Please make sure to update tests as appropriate.

