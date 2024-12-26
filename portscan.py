from scapy.all import *
import threading

tcpopen = []

def tcpscan(target, port_range):
    for port in port_range:
        response = sr1(IP(dst=target) / TCP(dport=port, flags="S"), timeout=3, verbose=0)
        if response and response.haslayer(TCP) and response[TCP].flags == "SA":
            tcpopen.append(port)
            print(f"Port {port} is open !!!")
        else:
            print(f"Port {port} is closed")

targetip = input("Enter target IP: ")
include_ephemeral = input("Include ephemeral (Y/N): ").strip().upper() == "Y"
ports = 65535 if include_ephemeral else 1024
processes = 64 # Increase or decrease as needed. Higher value = faster scanning but also higher CPU usage
chunks = ports // processes

ranges = [
    range(i * chunks + 1, (i + 1) * chunks + 1)
    for i in range(processes)
]

ranges[-1] = range((processes-1) * chunks + 1, ports + 1)

threads = []

for currentrange in ranges:
    thread = threading.Thread(target=tcpscan, args=(targetip, currentrange))
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()

print(f"Open ports: {sorted(tcpopen)}")
