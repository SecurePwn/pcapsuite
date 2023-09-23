import sys
import pyshark
import binascii

def scan_files(pcap_file):
    # Placeholder for actual scan functionality
    print(f"Scanning {pcap_file}...")

def banner():
    print(r'''
          ██████  ███████    ██████       █████   █     █  ██   █                                       
          █       █         █             █    █  █     █  █ █  █              
           ████   ███████  █         ███  █████   █  █  █  █  █ █                                  
               █  █         █             █       █ █ █ █  █   ██          
          ██████  ███████    ██████       █       ██   ██  █    █

          (Pre-Forensics & Penetration Tester's tool)
''')

def menu():
    banner="""
Author: @syedalizain033
Email: syedalizain03@gmail.com
Usage: python3 pycap.py <pcap file> <action> <required args>
Example: python3 pycap.py scan.pcap filescan '89 50 4E 47 0D 0A 1A 0A'
    """
    print(banner)
    
#-----------------------------------------------------------
def listActions():
    list={
        "scan":"Scan all PCAP file for all the results",
        "files":"Scan all the file magic bytes if existing",
        "file":"Provide magic bytes to scan. Example: -magic 05 05 05 05 "
    }
    return list
#-----------------------------------------------------------

def file(pcap, magic):
    print("Scanning for magic bytes...")
    
    # Open the pcap file
    try:
        all=''
        capture = pyshark.FileCapture(pcap)
        for p in capture:
            all=all+str(p)
        if magic in all:
            print("magic found")
    except FileNotFoundError:
        print(f"Error: The file '{pcap}' does not exist.")
        return

    magic_bytes = magic.replace(" ", "").upper()  # Remove spaces and convert to uppercase
    found_packets = []

    # Iterate through packets and find magic bytes
    for packet_number, packet in enumerate(capture):
        packet_hex = ''.join(packet.raw_mode.split(':')).upper()
        print(packet)

        if magic_bytes in packet_hex:
            protocol = packet.highest_layer
            source_ip = packet.ip.src
            destination_ip = packet.ip.dst

            found_packets.append({
                "packet_number": packet_number,
                "protocol": protocol,
                "source_ip": source_ip,
                "destination_ip": destination_ip
            })

    # Display results
    if found_packets:
        print(f"Found {len(found_packets)} packets with magic bytes:")
        for found_packet in found_packets:
            print(f"Magic byte '{magic}' found in:")
            print(f"Protocol: {found_packet['protocol']}")
            print(f"Packet number: {found_packet['packet_number']}")
            print(f"Source: {found_packet['source_ip']}")
            print(f"Destination: {found_packet['destination_ip']}")
            print("--------------------------")
    else:
        print("No packets with magic bytes found.")

#-----------------------------------------------------------

def main():
    if len(sys.argv)<2:
        banner()
        menu()
        sys.exit(0)
    try:
        pcap=sys.argv[1]
        if "file" in sys.argv[2]:
            magic=str(sys.argv[3])
            banner() #works fine till here.
            file(pcap,magic)

    except:
        listActions()
    
    
    # banner = build_banner()
    # print(banner)

    # if "scanall" in args.actions:
    #     scan_files(args.pcap_file)
    #     sys.exit(0)
    # if "file" in args.actions and "magic" in args.action:
    #     pass
    # else:
    #     print("Missing \"magic\" parameter. Correct syntax:- \npython3 -pcap file.pcap -action file -magic 05050505")

if __name__ == "__main__":
    main()
