# Covert Channel Sender with Encryption option

This Python program enables the creation of covert channels for transmitting files over IPv6 networks. The tool provides options for selecting various header types, protocols, and encryption methods to ensure secure and flexible data transmission.

## Features

- **Covert Channel Types**: Supports multiple IPv6 header fields for covert communication:
  - Traffic Class (TC)
  - Flow Label (FL)
  - Next Header (NH)
  - Hop Limit (HL)
  - Hop-by-Hop Options Header (HBH)
  - Routing Header (RH)
  - Destination Options Header (DO)
  - Fragment Header (FH)
- **Protocols**: IPv6, ICMPv6, UDP, and TCP.
- **Encryption**: Files can be encrypted using:
  - AES-CBC (16-byte key)
  - DES-CBC (8-byte key)
- **Automatic Key Handling**: Automatically generates keys if not provided.
- **File Validation**: Ensures the file exists and is non-empty before transmission.

## Prerequisites

- Python 3.x
- Required Python libraries:
  - `scapy`
  - `pycryptodome`
  - `psutil`
  - `netifaces`
- Valid IPv6 network setup.

Install the required libraries using:
```bash
pip install scapy pycryptodome psutil netifaces
```

## Usage

### Sending a File

To send a file using a covert channel, use the following command:

```bash
python3 covert_channel.py [interface] [options]
```

### Options

- `interface`: The network interface to use from the sender.
- `-smac`: The MAC address of the sender (resolved from the interface if skipping).
- `-dmac`: The MAC address of the receiver (resolved from the interface if skipping).
- `-sip`: The IPv6 address of the sender (resolved from the interface if skipping).
- `-dip`: The IPv6 address of the destination (default: `ff02::1` if skipping).
- `-t`: Choose one of the options to build the covert channel:
  - `TC`: Traffic Class
  - `FL`: Flow Label
  - `NH`: Next Header
  - `HL`: Hop Limit
  - `HBH`: Hop-by-Hop
  - `RH`: Routing Header
  - `DO`: Destination Option
  - `FH`: Fragment Header
- `-i`: Input file to send.
- `-a`: Choose one of the two options to encrypt (AES or DES).
- `-p`: Choose one of the options to build the protocol:
  - `IPv6`
  - `ICMPv6`
  - `UDP`
  - `TCP`
- `-k`: Insert the key to encrypt the file using the defined algorithm (automatically generated if skipping).

### Example
```bash
python3 covert_channel.py eth0 -smac 00:11:22:33:44:55 -dmac 66:77:88:99:AA:BB -sip fe80::1 -dip ff02::1 -t DO -i secret.txt -a AES -p ICMPv6 -k mysecretkey
```
