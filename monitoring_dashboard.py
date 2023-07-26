from flask import Flask, render_template, request
import requests
import jwt
import configparser

app = Flask(__name__)

API_URL = 'http://127.0.0.1:5000'

def get_token():
    config = configparser.ConfigParser()
    config.read('config.ini')
    SECRET_KEY = config.get('AUTHENTICATION', 'SECRET_KEY')
    expiration_time = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRATION_MINUTES)
    payload = {'exp': expiration_time}
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/status')
def get_status():
    try:
        token = get_token()
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(f'{API_URL}/status', headers=headers)
        response.raise_for_status()
        return response.json(), 200
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}, 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
