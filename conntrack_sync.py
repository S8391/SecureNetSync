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

# Define conntrack synchronization interval in seconds (set to 60 seconds by default)
SYNC_INTERVAL = 60

# AES encryption settings
AES_KEY_LENGTH = 32  # 32 bytes = 256 bits
AES_BLOCK_SIZE = 16

logging.basicConfig(filename='conntrack_sync.log', level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

class SSHClientWrapper:
    def __init__(self, hostname: str, timeout: int):
        self.hostname = hostname
        self.timeout = timeout
        self.client = None

    def __enter__(self):
        self.client = self.create_ssh_client(self.hostname, self.timeout)
        return self.client

    def __exit__(self, exc_type, exc_value, traceback):
        if self.client:
            self.client.close()

    def create_ssh_client(self, hostname: str, timeout: int) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, timeout=timeout)
        return client

def run_command(command: str) -> str:
    try:
        result = subprocess.check_output(command, shell=True, universal_newlines=True, stderr=subprocess.STDOUT)
        return result.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing command: {e.cmd}")
        logging.error(f"Command output: {e.output}")
        raise

def query_conntrack_table() -> str:
    command = 'conntrack -L --json'
    return run_command(command)

def deserialize_conntrack_data(data: str) -> dict:
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        logging.error(f"Failed to deserialize JSON data: {e}")
        raise

def apply_conntrack_data(data: dict, server: str):
    try:
        conntrack_json = json.dumps(data)
        encrypted_data = encrypt_data(conntrack_json)
        command = f'ssh {server} "echo \'{encrypted_data}\' | base64 -d | openssl enc -aes-256-cbc -d -a -kfile secret.key | conntrack -R --force"'
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to apply conntrack data on {server}: {e}")
        raise

def synchronize_conntrack(server: str, retries: int, retry_delay: int, ipv6: bool):
    try:
        # Step 1: Query local conntrack table
        local_conntrack_data = query_conntrack_table()

        # Step 2: Transfer data to central server
        remote_conntrack_data = transfer_data_to_central_server(local_conntrack_data, retries, retry_delay)

        # Step 3: Deserialize and apply data received from central server
        conntrack_data = deserialize_and_apply_data(remote_conntrack_data, server)

        # Step 4: Update connection tracking table on other servers
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = [executor.submit(transfer_data_to_server, conntrack_data, other_server, ipv6) for other_server in SERVERS if other_server != server]
            for future in futures:
                future.result()

        logging.info(f"Connection tracking data synchronized successfully on {server}.")
    except Exception as e:
        logging.error(f"An error occurred during synchronization on {server}: {e}")

def transfer_data_to_central_server(data: str, retries: int, retry_delay: int) -> str:
    for retry in range(retries + 1):
        try:
            with SSHClientWrapper(CENTRAL_SERVER, SSH_CONNECTION_TIMEOUT) as client:
                remote_conntrack_data = transfer_data_to_server(data, client)
                return remote_conntrack_data

        except paramiko.SSHException as e:
            logging.warning(f"Failed to transfer data to central server. Retrying ({retry}/{retries})...")
            if retry < retries:
                time.sleep(retry_delay)
            else:
                raise

def transfer_data_to_server(data: str, client: paramiko.SSHClient, ipv6: bool = False):
    with client.get_transport().open_session() as session:
        if ipv6:
            session.exec_command(f'echo \'{data}\' | base64 -d | openssl enc -aes-256-cbc -d -a -kfile secret.key | conntrack -R --force')
        else:
            session.exec_command(f'echo \'{data}\' | base64 -d | openssl enc -aes-256-cbc -d -a -kfile secret.key')
        remote_conntrack_data = session.makefile("r").read()
        session.recv_exit_status()

    return remote_conntrack_data

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

def deserialize_and_apply_data(encrypted_data: str, server: str) -> dict:
    decrypted_data = decrypt_data(encrypted_data)
    conntrack_data = json.loads(decrypted_data)
    apply_conntrack_data(conntrack_data, server)
    return conntrack_data

def create_ssh_client(hostname: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname, timeout=SSH_CONNECTION_TIMEOUT)
    return client

def synchronize_all_servers():
    try:
        # Step 6: Start synchronization threads for each server
        threads = [threading.Thread(target=synchronize_conntrack, args=(server, SSH_CONNECTION_RETRIES, SSH_CONNECTION_RETRY_DELAY, is_ipv6(server))) for server in SERVERS]
        for thread in threads:
            thread.start()

        # Step 7: Wait for all threads to complete
        for thread in threads:
            thread.join()

        logging.info("All servers' connection tracking data synchronized successfully.")
    except Exception as e:
        logging.error(f"An error occurred during synchronization: {e}")

def main():
    try:
        # Step 8: Ensure SSH keys are set up for passwordless connections between servers
        validate_ssh_key_setup()

        # Step 9: Synchronize the connection tracking data between all servers
        synchronize_all_servers()

        # Step 10: Schedule periodic synchronization
        schedule_periodic_sync()

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

def validate_ssh_key_setup():
    # Check if SSH keys are set up for passwordless connections between servers
    ssh_key_check_command = 'ssh -o BatchMode=yes -o ConnectTimeout=5 -o PasswordAuthentication=no ' + \
                            f'{CENTRAL_SERVER} "exit"'
    try:
        subprocess.run(ssh_key_check_command, shell=True, check=True)
    except subprocess.CalledProcessError:
        raise RuntimeError("SSH key-based authentication is not set up properly. " +
                           "Please ensure SSH keys are exchanged and set up for passwordless connections.")

def schedule_periodic_sync(interval: int = SYNC_INTERVAL):
    # Schedule periodic synchronization in the background
    threading.Timer(interval, schedule_periodic_sync, [interval]).start()
    synchronize_all_servers()

def is_ipv6(address: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return True
    except socket.error:
        return False

def get_aes_key() -> bytes:
    # Read the AES key from the secret.key file
    with open('secret.key', 'rb') as key_file:
        aes_key = key_file.read()

    if len(aes_key) != AES_KEY_LENGTH:
        raise ValueError("Invalid AES key length. Ensure that secret.key contains a 32-byte (256-bit) key.")

    return aes_key

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Conntrack Synchronization Script')
    parser.add_argument('--servers', metavar='SERVER', type=str, nargs='+', required=True,
                        help='List of server IP addresses or hostnames to synchronize')
    parser.add_argument('--central-server', metavar='CENTRAL_SERVER', type=str, required=True,
                        help='IP address or hostname of the central server')
    parser.add_argument('--ipv6', action='store_true', help='Use IPv6 for synchronization')
    args = parser.parse_args()

    SERVERS = args.servers
    CENTRAL_SERVER = args.central_server
    SSH_CONNECTION_TIMEOUT = 5
    SSH_CONNECTION_RETRIES = 3
    SSH_CONNECTION_RETRY_DELAY = 5
    MAX_THREADS = 10

    main()
