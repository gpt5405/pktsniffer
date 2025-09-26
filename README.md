# Homework 01 - pktsniffer

## Requirements
- Python 3.10+
- virtualenv (recommended)
- Install dependencies:
    python -m venv venv
    source venv/bin/activate   # or venv\Scripts\activate on Windows
    pip install -r requirements.txt

## Run
    python pktsniffer.py -r capture.pcap
    python pktsniffer.py -r capture.pcap -c 5
    python pktsniffer.py -r capture.pcap host 10.200.143.87
    python pktsniffer.py -r capture.pcap port 80
    python pktsniffer.py -r capture.pcap ip 10.200.143.87
    python pktsniffer.py -r capture.pcap tcp
    python pktsniffer.py -r capture.pcap udp
    python pktsniffer.py -r capture.pcap icmp
    python pktsniffer.py -r capture.pcap net 10.200.143.87/24

## Output
The program prints summary lines for Ethernet, IP, and transport headers (TCP/UDP/ICMP).

