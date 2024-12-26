from scapy.all import *

tcpopen = []

def tcpscan(target):
    for port in range(1,100):
        response = sr1(IP(dst=target) / TCP(dport=port, flags="S"), timeout=3, verbose=1)
        if response.haslayer(TCP) and response[TCP].flags == "SA":
            tcpopen.append(port)
            print(f"Port {port} is open")

targetip = input("Enter target IP: ")
tcpscan(targetip)
print(f"Open ports: {tcpopen}")


