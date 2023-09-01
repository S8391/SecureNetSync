from flask import Flask, render_template, request, jsonify, abort
import requests
import jwt
import configparser
from datetime import datetime, timedelta

app = Flask(__name__)

API_URL = 'http://127.0.0.1:5000'

# Read configuration from config.ini
config = configparser.ConfigParser()
config.read('config.ini')

# Load authentication secret key
SECRET_KEY = config.get('AUTHENTICATION', 'SECRET_KEY')

# Define token expiration time (in minutes)
TOKEN_EXPIRATION_MINUTES = config.getint('AUTHENTICATION', 'TOKEN_EXPIRATION_MINUTES')

def get_token():
    expiration_time = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRATION_MINUTES)
    payload = {'exp': expiration_time}
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

@app.route('/')
def index():
    return render_template('index.html')
# Needs updated as doesnt resolve correct load-status on the server-stacks 
@app.route('/status')
def get_status():
    try:
        token = get_token()
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(f'{API_URL}/status', headers=headers)
        response.raise_for_status()
        return jsonify(response.json()), 200
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Failed to fetch status.'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
