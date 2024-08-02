# Cira Packet Sniffer

## Overview

The Cira Packet Sniffer is a Python-based tool for capturing, analyzing, and logging network packets. It features a graphical user interface (GUI) built with `tkinter` and uses `scapy` for packet manipulation. This tool supports various functionalities including protocol decoding, packet filtering, search and export capabilities, and real-time packet analysis.

## Features

- **Protocol Decoding**: Decodes and displays detailed information for protocols such as HTTP, DNS, and manually parsed FTP data.
- **Packet Filtering**: Allows users to filter packets based on IP address, protocol, port number, etc.
- **Search and Export**: Provides functionality to search through captured packets and export them to PCAP files.
- **Real-time Analysis**: Implements basic real-time packet analysis.
- **Performance Optimization**: Designed to handle high traffic volumes efficiently.
- **Cross-Platform Support**: Runs on Windows, macOS, and Linux.

## Requirements

- Python 3.x
- `scapy`
- `tkinter` (typically included with Python)

## Installation

1. **Clone the Repository**:
   ```sh
   git clone https://github.com/TheHackerReshma/Packet-Sniffer.git

2.Install Dependencies:
Install the required Python libraries using pip:

pip install scapy tk


Usage
1.Run the Script:
python packet_sniffer.py

Usage
1.Run the Script:
python packet_sniffer.py

2.GUI Controls:

File Menu:
Start Sniffing: Begin capturing network packets.
Stop Sniffing: Stop capturing packets.
Export to PCAP: Save captured packets to a PCAP file.
Exit: Close the application.
Filter Menu:
Set Filter: Define filter criteria (IP address, protocol, port).
Search Menu:
Search Packets: Search through captured packets based on a search term.

Features in Detail
Protocol Decoding
The sniffer decodes and displays information for:

HTTP: HTTP request and response data.
FTP: FTP command and data packets (manually parsed from TCP payload).
DNS: DNS queries and responses.
Packet Filtering
Filters can be set for:

IP Address: Filter packets based on source or destination IP.
Protocol: Filter by protocol (e.g., TCP, UDP, HTTP, DNS).
Port Number: Filter packets by source or destination port.
Search and Export
Search: Allows users to search for specific terms in the captured packet data.
Export to PCAP: Save captured packets to a PCAP file for further analysis with tools like Wireshark.
Troubleshooting
Ensure you have the necessary permissions to capture network packets. You might need to run the script with elevated privileges (e.g., sudo on Linux or Administrator on Windows).
Verify that scapy and tkinter are installed correctly. Reinstall them if necessary.
FTP traffic is parsed manually from TCP payloads. Ensure that the TCP payload contains readable text data for FTP.


