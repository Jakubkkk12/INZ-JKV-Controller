# INZ-JKV-Controller
## Description

This project (INZ-JKV-Controller) is a controller application written in Python with web components for managing and monitoring network configuration especially for MPLS L3VPN and MPLS TE. It is part of the “JKV Controller” development project. It provides REST API endpoints to interact with the system.

Example REST API requests can be found here:
👉 https://www.postman.com/jkv2444/inz-controller-api/

## Setup / How to run

### 1 Clone the repository:

git clone https://github.com/Jakubkkk12/INZ-JKV-Controller.git
cd INZ-JKV-Controller


### 2 Create a virtual environment:

python3 -m venv venv
source venv/bin/activate   # Linux/macOS
or
venv\Scripts\activate      # Windows

### 3 Install dependencies:

pip install -r requirements.txt


### 4 Set up environment variables

Open the .env file

Change the value of SECRET_KEY to your own secure key

Run the application:

python main.py

