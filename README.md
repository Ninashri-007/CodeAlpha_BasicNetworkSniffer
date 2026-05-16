# Basic Network Sniffer

## Objective
This project is a Python-based network sniffer that captures and analyzes network packets using Scapy.

## Features
- Captures live network packets
- Displays source and destination IP addresses
- Detects protocols (TCP/UDP)
- Displays packet payloads
- Saves packet logs

## Technologies Used
- Python
- Scapy

## Windows Requirement

This project requires Npcap for packet sniffing on Windows.

Download:
https://npcap.com/#download

During installation enable:
- WinPcap API-compatible Mode

## Installation

Install Scapy:

```bash
pip install scapy
```

## How to Run

Run the program:

```bash
python sniffer.py
```

## Sample Output

Source IP      : 192.168.1.5
Destination IP : 142.250.183.78
Protocol       : TCP

## Learning Outcomes
- Learned packet sniffing concepts
- Understood TCP/IP protocols
- Learned basic network traffic analysis

## Author
Ninashri
