from flask import Flask, request, jsonify, abort
from functools import wraps
from datetime import datetime, timedelta
import jwt
import configparser
import json
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import sqlite3

app = Flask(__name__)

# Read configuration from config.ini
config = configparser.ConfigParser()
config.read('config.ini')

# Load authentication secret key
SECRET_KEY = config.get('AUTHENTICATION', 'SECRET_KEY')

# Define token expiration time (in minutes)
TOKEN_EXPIRATION_MINUTES = config.getint('AUTHENTICATION', 'TOKEN_EXPIRATION_MINUTES')

# Load exclusion list
EXCLUSION_LIST = set()
if os.path.exists('exclusion_list.ini'):
    with open('exclusion_list.ini', 'r') as exclusion_file:
        EXCLUSION_LIST = {entry.strip() for entry in exclusion_file if entry.strip()}

# AES encryption settings
AES_KEY_LENGTH = 32  # 32 bytes = 256 bits
AES_BLOCK_SIZE = 16

DATABASE_FILE = 'connection_tracking.db'
CONNECTION_TABLE_NAME = 'connection_tracking'

def create_connection_table():
    # Create the connection tracking table if it doesn't exist
    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()

    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {CONNECTION_TABLE_NAME} (
            connection_id TEXT PRIMARY KEY,
            source_ip TEXT,
            destination_ip TEXT,
            port INT,
            protocol TEXT
        )
    ''')

    connection.commit()
    connection.close()

def generate_token():
    expiration_time = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRATION_MINUTES)
    payload = {'exp': expiration_time}
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def requires_auth(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            abort(401, description='Missing authentication token.')

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            if 'exp' not in payload or datetime.utcfromtimestamp(payload['exp']) < datetime.utcnow():
                abort(401, description='Token has expired.')
        except jwt.ExpiredSignatureError:
            abort(401, description='Token has expired.')
        except jwt.InvalidTokenError:
            abort(401, description='Invalid token.')

        return func(*args, **kwargs)

    return decorated

def encrypt_data(data: str) -> str:
    # Generate random AES key and initialization vector
    aes_key = get_random_bytes(AES_KEY_LENGTH)
    iv = get_random_bytes(AES_BLOCK_SIZE)

    # Create AES cipher with CFB mode
    cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)

    # Encrypt the data
    encrypted_data = cipher.encrypt(data.encode('utf-8'))

    # Combine the IV and encrypted data and encode to base64
    encrypted_data = b64encode(iv + encrypted_data).decode('utf-8')

    return encrypted_data

def decrypt_data(encrypted_data: str) -> str:
    # Decode the base64 encrypted data
    encrypted_data = b64decode(encrypted_data)

    # Extract the IV from the data
    iv = encrypted_data[:AES_BLOCK_SIZE]

    # Create AES cipher with CFB mode using the saved IV
    aes_key = get_random_bytes(AES_KEY_LENGTH)
    cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)

    # Decrypt the data and return as string
    decrypted_data = cipher.decrypt(encrypted_data[AES_BLOCK_SIZE:]).decode('utf-8')

    return decrypted_data

@app.route('/token', methods=['POST'])
def get_token():
    token = generate_token()
    return jsonify({'token': token})

@app.route('/apply', methods=['POST'])
@requires_auth
def apply_conntrack_data():
    try:
        encrypted_data = request.get_data().decode('utf-8')
        data = decrypt_data(encrypted_data)
        conntrack_data = deserialize_conntrack_data(data)
        apply_conntrack_data_to_db(conntrack_data)  # Rename to avoid naming conflict
        return jsonify({'message': 'Connection tracking data applied successfully.'}), 200
    except ValueError as e:  # Catch the specific exception for JSON decoding error
        return jsonify({'error': 'Invalid data format.'}), 400
    except Exception as e:
        return jsonify({'error': 'An internal server error occurred.'}), 500

def deserialize_conntrack_data(data: str) -> dict:
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to deserialize JSON data: {e}")

def apply_conntrack_data_to_db(data: dict):  # Rename to avoid naming conflict
    try:
        # Apply the conntrack data to the local conntrack table
        create_connection_table()

        connection = sqlite3.connect(DATABASE_FILE)
        cursor = connection.cursor()

        for connection_id, connection_info in data.items():
            if connection_id not in EXCLUSION_LIST:
                if connection_id in get_active_connection_ids(cursor):  # Helper function to get active connection IDs
                    # Update existing connection entry
                    update_connection(cursor, connection_id, connection_info)
                else:
                    # Create a new connection entry
                    create_connection(cursor, connection_id, connection_info)

        # Perform cleanup of stale connections not present in the data
        cleanup_stale_connections(cursor, data.keys())

        connection.commit()
        connection.close()

        print("Connection tracking data applied successfully.")
    except Exception as e:
        print("An error occurred while applying connection tracking data:", e)

def get_active_connection_ids(cursor):  # Helper function to get active connection IDs
    cursor.execute(f'SELECT connection_id FROM {CONNECTION_TABLE_NAME}')
    return set(row[0] for row in cursor.fetchall())

def update_connection(cursor, connection_id: str, connection_info: dict):  # Pass cursor as an argument
    # Perform update of an existing connection entry in the connection tracking table
    cursor.execute(f'''
        UPDATE {CONNECTION_TABLE_NAME}
        SET source_ip = ?, destination_ip = ?, port = ?, protocol = ?
        WHERE connection_id = ?
    ''', (connection_info['source_ip'], connection_info['destination_ip'], connection_info['port'], connection_info['protocol'], connection_id))

def create_connection(cursor, connection_id: str, connection_info: dict):  # Pass cursor as an argument
    # Perform creation of a new connection entry in the connection tracking table
    cursor.execute(f'''
        INSERT INTO {CONNECTION_TABLE_NAME} (connection_id, source_ip, destination_ip, port, protocol)
        VALUES (?, ?, ?, ?, ?)
    ''', (connection_id, connection_info['source_ip'], connection_info['destination_ip'], connection_info['port'], connection_info['protocol']))

def cleanup_stale_connections(cursor, active_connection_ids: set):  # Pass cursor as an argument
    # Perform cleanup of connections that are not present in the active_connection_ids
    # These connections are considered stale and can be removed from the connection tracking table
    cursor.execute(f'''
        DELETE FROM {CONNECTION_TABLE_NAME}
        WHERE connection_id NOT IN ({','.join(['?'] * len(active_connection_ids))})
    ''', tuple(active_connection_ids))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
