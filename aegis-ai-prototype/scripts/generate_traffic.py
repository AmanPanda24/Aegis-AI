#!/usr/bin/env python3
"""
Traffic Generator for Aegis-AI Prototype
Simulates network traffic between VMs for testing.
Requires root privileges for live packet injection.
"""

import time
import random
import argparse

try:
    from scapy.all import IP, TCP, UDP, send
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[WARN] Scapy not installed. Install with: pip install scapy")

def generate_normal_traffic(dst_ip, duration=60):
    print(f"[GEN] Generating normal traffic to {dst_ip}...")
    start = time.time()
    while time.time() - start < duration:
        sport = random.randint(40000, 60000)
        pkt = IP(dst=dst_ip)/TCP(sport=sport, dport=80, flags='PA')/b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        if SCAPY_AVAILABLE:
            send(pkt, verbose=0)
        time.sleep(random.uniform(0.1, 1.0))

def generate_port_scan(dst_ip):
    print(f"[GEN] Port scanning {dst_ip}...")
    for port in random.sample(range(1, 1000), 50):
        pkt = IP(dst=dst_ip)/TCP(sport=random.randint(40000, 60000), dport=port, flags='S')
        if SCAPY_AVAILABLE:
            send(pkt, verbose=0)
        time.sleep(0.01)

def generate_dos(dst_ip, duration=10):
    print(f"[GEN] DoS attack on {dst_ip}...")
    start = time.time()
    while time.time() - start < duration:
        pkt = IP(dst=dst_ip)/TCP(sport=random.randint(40000, 60000), dport=80, flags='S')
        if SCAPY_AVAILABLE:
            send(pkt, verbose=0)
        if random.random() > 0.9:
            time.sleep(0.001)

def generate_brute_force(dst_ip):
    print(f"[GEN] Brute forcing {dst_ip}:22...")
    for _ in range(30):
        sport = random.randint(40000, 60000)
        pkt = IP(dst=dst_ip)/TCP(sport=sport, dport=22, flags='S')
        if SCAPY_AVAILABLE:
            send(pkt, verbose=0)
        time.sleep(0.2)

def main():
    parser = argparse.ArgumentParser(description='Generate test traffic for Aegis-AI')
    parser.add_argument('--target', type=str, default='192.168.100.10', help='Target IP')
    parser.add_argument('--scenario', type=str, default='normal', choices=['normal', 'portscan', 'dos', 'bruteforce', 'all'])
    parser.add_argument('--duration', type=int, default=60, help='Duration in seconds')
    args = parser.parse_args()

    if not SCAPY_AVAILABLE:
        print("[ERROR] Cannot generate live traffic without scapy. Use simulation mode instead.")
        return

    if args.scenario == 'normal':
        generate_normal_traffic(args.target, args.duration)
    elif args.scenario == 'portscan':
        generate_port_scan(args.target)
    elif args.scenario == 'dos':
        generate_dos(args.target, args.duration)
    elif args.scenario == 'bruteforce':
        generate_brute_force(args.target)
    elif args.scenario == 'all':
        print("[GEN] Running full scenario suite...")
        generate_normal_traffic(args.target, 30)
        time.sleep(2)
        generate_port_scan(args.target)
        time.sleep(2)
        generate_dos(args.target, 10)
        time.sleep(2)
        generate_brute_force(args.target)

    print("[GEN] Traffic generation complete.")

if __name__ == "__main__":
    main()
