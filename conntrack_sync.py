import argparse
import subprocess
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
import paramiko
import time
from typing import List, Tuple, Optional
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import os
import socket
import configparser
from flask import Flask, request, jsonify, abort
from functools import wraps
from datetime import datetime, timedelta
import jwt

app = Flask(__name__)

# Define conntrack synchronization interval in seconds (set to 60 seconds by default)
SYNC_INTERVAL = 60

# AES encryption settings
AES_KEY_LENGTH = 32  # 32 bytes = 256 bits
AES_BLOCK_SIZE = 16

logging.basicConfig(filename='conntrack_sync.log', level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def load_auth_token():
    with open('secret.key', 'rb') as key_file:
        auth_token = key_file.read()
    return auth_token

def get_auth_headers():
    auth_token = load_auth_token()
    return {'Authorization': f'Bearer {auth_token.decode("utf-8")}'}

def load_exclusion_list():
    config = configparser.ConfigParser()
    config.read('exclusion_list.ini')
    exclusion_list = {entry.strip() for entry in config['EXCLUSION_LIST']['Entries'].split('\n') if entry.strip()}
    return exclusion_list

def query_conntrack_table() -> str:
    command = 'conntrack -L --json'
    return run_command(command)

def run_command(command: str) -> str:
    try:
        result = subprocess.check_output(command, shell=True, universal_newlines=True, stderr=subprocess.STDOUT)
        return result.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing command: {e.cmd}")
        logging.error(f"Command output: {e.output}")
        raise

def deserialize_conntrack_data(data: str) -> dict:
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        logging.error(f"Failed to deserialize JSON data: {e}")
        raise

def encrypt_data(data: str) -> str:
    # Generate random AES key and initialization vector
    aes_key = get_aes_key()
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
    aes_key = get_aes_key()
    cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)

    # Decrypt the data and return as string
    decrypted_data = cipher.decrypt(encrypted_data[AES_BLOCK_SIZE:]).decode('utf-8')

    return decrypted_data

def apply_conntrack_data(data: dict, server: str):
    try:
        conntrack_json = json.dumps(data)
        encrypted_data = encrypt_data(conntrack_json)
        auth_headers = get_auth_headers()
        command = f'curl -X POST {server}/apply -H "Content-Type: application/json" -H "Authorization: Bearer {auth_headers["Authorization"]}" -d "{encrypted_data}"'
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to apply conntrack data on {server}: {e}")
        raise

def synchronize_conntrack(server: str, retries: int, retry_delay: int, ipv6: bool, exclusion_list: set):
    try:
        # Step 1: Query local conntrack table
        local_conntrack_data = query_conntrack_table()

        # Step 2: Transfer data to central server
        remote_conntrack_data = transfer_data_to_central_server(local_conntrack_data, retries, retry_delay)

        # Step 3: Deserialize and apply data received from central server
        conntrack_data = deserialize_and_apply_data(remote_conntrack_data, server)

        # Step 4: Exclude data from the conntrack table based on the exclusion list
        conntrack_data = exclude_data(conntrack_data, exclusion_list)

        # Step 5: Update connection tracking table on other servers
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = [executor.submit(transfer_data_to_server, conntrack_data, other_server, ipv6) for other_server in SERVERS if other_server != server]
            for future in futures:
                future.result()

        logging.info(f"Connection tracking data synchronized successfully on {server}.")
    except Exception as e:
        logging.error(f"An error occurred during synchronization on {server}: {e}")

def get_aes_key():
    aes_key_file = 'secret.key'
    if os.path.exists(aes_key_file):
        with open(aes_key_file, 'rb') as file:
            return file.read(AES_KEY_LENGTH)
    else:
        raise FileNotFoundError("AES key file not found. Generate an AES key and store it in 'secret.key'.")

def transfer_data_to_central_server(data: str, retries: int, retry_delay: int) -> str:
    central_server = CENTRAL_SERVER
    logging.info(f"Transferring conntrack data to central server {central_server}...")
    encrypted_data = encrypt_data(data)
    auth_headers = get_auth_headers()

    for _ in range(retries + 1):
        try:
            command = f'curl -X POST {central_server}/transfer -H "Content-Type: application/json" -H "Authorization: Bearer {auth_headers["Authorization"]}" -d "{encrypted_data}"'
            response = subprocess.check_output(command, shell=True, universal_newlines=True, stderr=subprocess.STDOUT)
            decrypted_response = decrypt_data(response.strip())
            return decrypted_response
        except subprocess.CalledProcessError as e:
            logging.warning(f"Failed to transfer data to central server: {e.output}")
            time.sleep(retry_delay)
        except Exception as e:
            logging.error(f"An error occurred during data transfer to central server: {e}")
            raise

    raise Exception("Failed to transfer data to central server after retries.")

def transfer_data_to_server(data: str, server: str, ipv6: bool):
    logging.info(f"Transferring conntrack data to server {server}...")
    encrypted_data = encrypt_data(data)

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh_client.connect(server, username=SSH_USERNAME, key_filename=SSH_KEY_FILE)
        command = f'curl -X POST {server}/transfer -H "Content-Type: application/json" -d "{encrypted_data}"'
        stdin, stdout, stderr = ssh_client.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            logging.warning(f"Failed to transfer data to server {server}: {stderr.read().decode()}")
        else:
            logging.info(f"Connection tracking data transferred to server {server}.")
    except paramiko.SSHException as e:
        logging.warning(f"Failed to establish SSH connection to server {server}: {e}")
    except socket.timeout as e:
        logging.warning(f"SSH connection to server {server} timed out: {e}")
    except Exception as e:
        logging.error(f"An error occurred during data transfer to server {server}: {e}")
    finally:
        ssh_client.close()

def exclude_data(data: dict, exclusion_list: set) -> dict:
    return {key: value for key, value in data.items() if key not in exclusion_list}

def deserialize_and_apply_data(encrypted_data: str, server: str) -> dict:
    decrypted_data = decrypt_data(encrypted_data)
    conntrack_data = deserialize_conntrack_data(decrypted_data)
    apply_conntrack_data(conntrack_data, server)
    return conntrack_data

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Real-time synchronization of conntrack connections across multiple servers.")
    parser.add_argument('--servers', required=True, nargs='+', help="List of server IP addresses or hostnames to synchronize conntrack data.")
    parser.add_argument('--central-server', required=True, help="Central server IP address or hostname to store shared conntrack data.")
    parser.add_argument('--ipv6', action='store_true', help="Use IPv6 for synchronization.")
    args = parser.parse_args()

    # Read configuration from config.ini
    config = configparser.ConfigParser()
    config.read('config.ini')
    SSH_USERNAME = config.get('SSH', 'SSH_USERNAME')
    SSH_KEY_FILE = config.get('SSH', 'SSH_KEY_FILE')
    MAX_THREADS = config.getint('GENERAL', 'MAX_THREADS')

    SERVERS = args.servers
    CENTRAL_SERVER = args.central_server

    # Load exclusion list
    exclusion_list = load_exclusion_list()

    try:
        auth_headers = get_auth_headers()

        # Step 1: Perform status check on all servers
        for server in SERVERS:
            status_check(server, auth_headers)

        # Step 2: Synchronize conntrack data on all servers
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = [executor.submit(synchronize_conntrack, server, config.getint('SSH', 'SSH_CONNECTION_RETRIES'), config.getint('SSH', 'SSH_CONNECTION_RETRY_DELAY'), args.ipv6, exclusion_list) for server in SERVERS]
            for future in futures:
                future.result()

        # Step 3: Wait for the next synchronization interval
        time.sleep(SYNC_INTERVAL)

    except KeyboardInterrupt:
        logging.info("Conntrack synchronization script terminated by user.")
    except Exception as e:
        logging.error(f"An error occurred during conntrack synchronization: {e}")
