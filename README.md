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
   git clone https://github.com/yourusername/advanced-packet-sniffer.git
   cd cira-packet-sniffer
