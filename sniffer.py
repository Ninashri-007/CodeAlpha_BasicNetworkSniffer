from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from colorama import init, Fore
from datetime import datetime

# Initialize colorama
init(autoreset=True)

packet_count = 0

print("=" * 55)
print("           BASIC NETWORK SNIFFER")
print("=" * 55)
print("Capturing packets...")
print("Press CTRL + C to stop.\n")


def process_packet(packet):
    global packet_count
    packet_count += 1

    current_time = datetime.now().strftime("%H:%M:%S")

    print("\n" + "=" * 55)
    print(f"{Fore.CYAN}Packet Number : {packet_count}")
    print(f"{Fore.CYAN}Time          : {current_time}")

    # Check if packet contains IP layer
    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        # Detect protocol type
        if protocol == 6:
            protocol_name = "TCP"
            color = Fore.GREEN

        elif protocol == 17:
            protocol_name = "UDP"
            color = Fore.YELLOW

        elif protocol == 1:
            protocol_name = "ICMP"
            color = Fore.RED

        else:
            protocol_name = "OTHER"
            color = Fore.WHITE

        print(f"{color}Source IP      : {src_ip}")
        print(f"{color}Destination IP : {dst_ip}")
        print(f"{color}Protocol       : {protocol_name}")

        # Packet size
        print(f"{Fore.MAGENTA}Packet Size    : {len(packet)} bytes")

        # Payload extraction
        payload = bytes(packet.payload)

        if payload:
            print(f"{Fore.BLUE}Payload        : {payload[:100]}")

        # Save logs to file
        with open("packet_logs.txt", "a") as log_file:
            log_file.write(
                f"{current_time} | "
                f"Packet #{packet_count} | "
                f"{src_ip} -> {dst_ip} | "
                f"{protocol_name} | "
                f"{len(packet)} bytes\n"
            )

    else:
        print(f"{Fore.RED}Non-IP Packet Detected")


# Start sniffing
try:
    # Change "Wi-Fi" if your adapter name is different
    sniff(
        iface="Wi-Fi",
        prn=process_packet,
        store=False
    )

except KeyboardInterrupt:
    print("\n" + "=" * 55)
    print(f"{Fore.RED}Sniffer stopped by user.")
    print("=" * 55)

except Exception as e:
    print(f"{Fore.RED}Error: {e}")