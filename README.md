# Conntrack Synchronization Script

![Python](https://img.shields.io/badge/python-3.6%20%7C%203.7%20%7C%203.8%20%7C%203.9-blue)
![License](https://img.shields.io/badge/license-MIT-green)

The `conntrack_sync.py` is a powerful Python script designed to achieve real-time synchronization of conntrack connections across multiple servers without the need for conntrackd. By leveraging SSH key-based authentication and AES encryption, it ensures secure and efficient data transfer between servers. This script is perfect for maintaining consistent network state across distributed environments, enabling seamless conntrack synchronization with minimal overhead. With additional features like periodic synchronization, detailed logging, and support for IPv4 and IPv6, it provides a robust and flexible solution for managing conntrack data synchronization in a variety of network setups.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [SSH Key Setup](#ssh-key-setup)
- [AES Encryption Setup](#aes-encryption-setup)
- [Options](#options)
- [API Usage](#api-usage)
- [Database Setup](#database-setup)
- [Troubleshooting](#troubleshooting) 
- [Logging](#logging)
- [Contributing](#contributing)
- [License](#license)

## Introduction

The `conntrack_sync.py` script allows you to synchronize the connection tracking data (conntrack) between multiple servers. It uses SSH key-based authentication for secure data transfer and operates in real-time without the need for additional software like `conntrackd`.


## Features

- Real-time synchronization of conntrack connections between servers.
- Support for multiple servers and a central server to store the shared data.
- Optional periodic synchronization for continuous data update.
- Flexible and configurable with customizable SSH timeout and retry settings.
- Detailed logging for monitoring and debugging.
- Progress bar during synchronization.
- AES encryption for data security.
- Command-line argument parsing for interactive setup.
- IPv4 and IPv6 support.

**In Active Development:**

- [ ] Configuration File (config.ini)
- [ ] Status Check

**Coming Soon:**

- [ ] Exclusion List
- [ ] Custom Logging Levels
- [ ] Monitoring Dashboard
- [ ] Alerting and Notifications
- [ ] Selective Synchronization


## Installation

1. Clone this repository to your local machine: `git clone https://github.com/S00013/Conntrack-Synchronization-Script.git`
2. Navigate to the project directory: `cd Conntrack-Synchronization-Script`


3. Install the required dependencies:
* For Windows:
  ```
  pip install -r requirements.txt
  ```

* For Linux:
  ```
  pip3 install -r requirements.txt
  ```


## Usage

1. Ensure SSH keys are set up for passwordless connections between the servers. If not set up, refer to the [SSH Key Setup](#ssh-key-setup) section for instructions.

2. Replace the placeholder IP addresses or hostnames in the `SERVERS` and `CENTRAL_SERVER` variables in the `conntrack_sync.py` script with the actual IP addresses or hostnames of your servers.

3. Run the script using Python:

```
   python conntrack_sync.py --servers server1_ip_or_hostname server2_ip_or_hostname server3_ip_or_hostname --central-server central_server_ip_or_hostname
```
Optional: To use IPv6 for synchronization, add the `--ipv6` flag.


4. To use the monitoring dashboard, run the following command: `python monitoring_dashboard.py`

Open your web browser and access the dashboard at `http://127.0.0.1:8000`.


## Configuration

You can configure the script behavior by modifying the values in the `config.ini` file:

### Authentication Settings
- `SECRET_KEY`: The secret key used for JWT token generation and validation.

### Token Settings
- `TOKEN_EXPIRATION_MINUTES`: The expiration time (in minutes) for the JWT authentication token.

### Connection Settings
- `SSH_CONNECTION_TIMEOUT`: The timeout (in seconds) for SSH connections to the servers.
- `SSH_CONNECTION_RETRIES`: The number of retries in case of SSH connection failures.
- `SSH_CONNECTION_RETRY_DELAY`: The delay (in seconds) between SSH connection retries.
- `MAX_THREADS`: The maximum number of threads to use for synchronization.
- `SYNC_INTERVAL`: The synchronization interval (in seconds) for periodic synchronization.

### AES Encryption Settings
- `AES_KEY_LENGTH`: The length of the AES encryption key in bytes.
- `AES_BLOCK_SIZE`: The AES encryption block size in bytes.


## SSH Key Setup

For the script to work, SSH key-based authentication must be set up between the servers. Follow these steps to set up passwordless SSH access:

1. Generate an SSH key pair on the local machine (if not already generated): `ssh-keygen -t rsa -b 4096`

2. Copy the public key to the remote servers (replace `server_ip` with the actual IP address or hostname): `ssh user@server_ip`

If you can log in without entering a password, SSH key-based authentication is set up correctly.


## AES Encryption Setup

1. Generate an AES secret key file named `secret.key` with a length of 32 bytes (256 bits). You can use the following command:

```
   python -c "from Crypto.Random import get_random_bytes; key = get_random_bytes(32); open('secret.key', 'wb').write(key)"
```

2. Ensure that the `secret.key` file is located in the same directory as the `conntrack_sync.py` script. The script will use this key for AES encryption and decryption during data transfer.


## Options

The script provides the following optional parameters:
```
   usage: conntrack_sync.py [-h] [--interval INTERVAL] [--ipv6]

   optional arguments:
   -h, --help show this help message and exit
   --interval INTERVAL Set the synchronization interval in seconds for periodic synchronization (default: 60 seconds).
   --ipv6 Use IPv6 for synchronization.
```

## API Usage

The Conntrack Synchronization Script provides an API that allows clients to synchronize connection tracking data. The API is built using Flask and provides two main endpoints:

### 1. Get Token

To access the API's endpoints, clients need to obtain an authentication token. To get the token, make a POST request to the `/token` endpoint: `POST http://127.0.0.1:5000/token`

The response will contain the JWT token, which can be used to authenticate subsequent requests to protected endpoints.

### 2. Apply Conntrack Data

To synchronize conntrack data, clients can make a POST request to the `/apply` endpoint: `POST http://127.0.0.1:5000/apply`

The conntrack data should be encrypted and included in the request body. The API will decrypt and apply the conntrack data to the local conntrack table.

**Note:** Ensure that the request includes the 'Authorization' header with the JWT token obtained from the `/token` endpoint.


## Database Setup

The `api.py` script uses SQLite to store connection tracking data. Before running the script, make sure to create an SQLite database file named `connection_tracking.db` in the same directory as the `api.py` script. The script will automatically create the necessary table (`connection_tracking`) to store the conntrack data on the first run.

To create the SQLite database and table, you can run the following command:

```
python -c "import sqlite3; connection = sqlite3.connect('connection_tracking.db'); cursor = connection.cursor(); cursor.execute('''CREATE TABLE IF NOT EXISTS connection_tracking (
connection_id TEXT PRIMARY KEY,
source_ip TEXT,
destination_ip TEXT,
port INT,
protocol TEXT
)'''); connection.commit(); connection.close()"
```
With the database set up, the `api.py` script will be ready to handle conntrack data synchronization requests.


## Logging

The script logs its activity to a file named `conntrack_sync.log` in the current working directory. You can monitor this log file for synchronization status and any potential errors.


## Troubleshooting

If you encounter any issues while using the Conntrack Synchronization Script, here are some common problems and their possible solutions:

1. **SSH Key Authentication Fails**: Double-check that you have correctly set up SSH key-based authentication between the servers. Ensure that the public key is added to the remote servers' `authorized_keys` file.

2. **AES Key Missing**: Make sure that the `secret.key` file with the AES secret key is present in the same directory as `conntrack_sync.py`.

3. **Token Expiration**: If you receive 'Token has expired' errors, ensure that your system clock is accurate. The token's expiration time is sensitive to time discrepancies.

4. **API Requests Fail**: Check that the API is running and accessible at the specified URL (default: `http://127.0.0.1:5000`). Verify that the correct token is included in the request headers for protected endpoints.



## Contributing

Contributions are welcome! If you have any suggestions, bug reports, or improvements, please open an issue or submit a pull request.


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.






























