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
- [Options](#options)
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


## Installation

1. Clone this repository to your local machine:

* `git clone https://github.com/yourusername/conntrack-sync.git` 
* `cd conntrack-sync`

2. Install the required dependencies: `pip install -r requirements.txt`



## Usage

1. Ensure SSH keys are set up for passwordless connections between the servers. If not set up, refer to the [SSH Key Setup](#ssh-key-setup) section for instructions.

2. Replace the placeholder IP addresses or hostnames in the `SERVERS` and `CENTRAL_SERVER` variables in the `conntrack_sync.py` script with the actual IP addresses or hostnames of your servers.

3. Run the script using Python: `python conntrack_sync.py --servers server1_ip_or_hostname server2_ip_or_hostname server3_ip_or_hostname --central-server central_server_ip_or_hostname`

Optional: To use IPv6 for synchronization, add the `--ipv6` flag.

The script will synchronize the conntrack data between all servers and store the shared data on the central server.



## Configuration

You can configure the script behavior by modifying the constants in the `conntrack_sync.py` script:

- `SSH_CONNECTION_TIMEOUT`: The timeout (in seconds) for SSH connections to the servers.
- `SSH_CONNECTION_RETRIES`: The number of retries in case of SSH connection failures.
- `SSH_CONNECTION_RETRY_DELAY`: The delay (in seconds) between SSH connection retries.
- `MAX_THREADS`: The maximum number of threads to use for synchronization.
- `SYNC_INTERVAL`: The synchronization interval (in seconds) for periodic synchronization.
- `AES_KEY_LENGTH`: The length of the AES encryption key in bytes.
- `AES_BLOCK_SIZE`: The AES encryption block size in bytes.


## SSH Key Setup

For the script to work, SSH key-based authentication must be set up between the servers. Follow these steps to set up passwordless SSH access:

1. Generate an SSH key pair on the local machine (if not already generated): `ssh-keygen -t rsa -b 4096`

2. Copy the public key to the remote servers (replace `server_ip` with the actual IP address or hostname): `ssh-copy-id user@server_ip`

3. Test SSH access to each server to ensure passwordless login is working: `ssh user@server_ip`

If you can log in without entering a password, SSH key-based authentication is set up correctly.



## Options

The script provides the following optional parameters:
```
usage: conntrack_sync.py [-h] [--interval INTERVAL] [--ipv6]

optional arguments:
-h, --help show this help message and exit
--interval INTERVAL Set the synchronization interval in seconds for periodic synchronization (default: 60 seconds).
--ipv6 Use IPv6 for synchronization.
```

## Logging

The script logs its activity to a file named `conntrack_sync.log` in the current working directory. You can monitor this log file for synchronization status and any potential errors.

## Contributing

Contributions are welcome! If you have any suggestions, bug reports, or improvements, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.



























