import pyshark

def file(pcap, magic):
    print("Scanning for magic bytes...")
    
    # Open the pcap file
    try:
        capture = pyshark.FileCapture(pcap, keep_packets=False)
        # capture.set_debug()
        for packet in capture:
            pkt=str(packet)
            hexData=''.join([hex(ord(char))[2:] for char in pkt])
            # magic=magic.replace(' ','')
            if "706e67" in str(hexData):
                print(pkt)
            # print(hexData)
            
        print("not found")
            
            
    except FileNotFoundError:
        print(f"Error: The file '{pcap}' does not exist.")
        return

def method2(pcap,magic):
    from scapy.all import rdpcap
    num=0
    protocols = {
    "FTP": 0,
    "HTTP": 0,
    "SSH": 0,
    # Add more protocols as needed
}
   
    pcap = rdpcap(pcap)
    protocol_counts = {}
    http_count = 0
    ftp_count = 0
    for packet in pcap:
        if packet.haslayer("TCP"):
            src_port = packet.getlayer("TCP").sport
            dst_port = packet.getlayer("TCP").dport
            
            if src_port == 80 or dst_port == 80:
                http_count += 1
            if src_port == 20 or dst_port == 20 or src_port == 21 or dst_port == 21:
                ftp_count += 1
    print(f"HTTP:{http_count} \nFTP: {ftp_count}")


pcap="file.pcap"
magic="706e67"
file(pcap,magic)
