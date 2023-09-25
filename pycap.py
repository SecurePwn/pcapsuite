import sys
import pyshark
import binascii
from flask_app.investigation import *

def scan_files(pcap_file):
    # Placeholder for actual scan functionality
    print(f"Scanning {pcap_file}...")

def banner():
    print(r'''
          ██████  ███████     ███████       ██████   █     █  ██    █                                       
          █       █          █              █    █   █     █  █ █   █              
           ████   ███████  █           ███  ██████   █  █  █  █  █  █                                  
               █  █          █              █        █ █ █ █  █   █ █          
          ██████  ███████     ███████       █        ██   ██  █    ██

          (Pre-Forensics & Penetration Tester's tool)
          (This tool gives false positive too, but I never try to skip them.)
''')

def menu():
    banner="""
Author: @syedalizain033
Email: syedalizain03@gmail.com
Usage: python3 pycap.py <pcap file> --<action> <required args if any>
Example: python3 pycap.py scan.pcap --scanmagic '89 50 4E 47 0D 0A 1A 0A'
    """
    print(banner)
    
#-----------------------------------------------------------
def listActions():
    list={
        "--scan_magic_detail":"Scan all PCAP file for all the results",
        "--scan_magics":"Scan all the file magic bytes if existing and get total numbers estimated",
        "--magicbyte":"Provide magic bytes to scan. Example: \"05 05 05 05\" or \"05050505\""
    }
    for i in list:
        print(f"{i}:     {list[i]}")
#-----------------------------------------------------------



#-----------------------------------------------------------

def main():
    if len(sys.argv)<2:
        banner()
        menu()
        listActions()
        sys.exit(0)
    try:
        banner()
        pcap=sys.argv[1]
        if "--scan_magics" in sys.argv[2]:
           data=magic_bytes_find_all(pcap) 
           for i in data:
               print(f"{i}: {data[i]}")
        elif "--scan_magic_detail" in sys.argv[2]:
            from prettytable import PrettyTable
            data=file_scan(pcap)
            table=PrettyTable()
            table.field_names=["File name","Magic Byte","Packet No.","Source IP","Destination IP","Packet Data with port","Source Port","Destination Port"]
            for row in data:
                table.add_row(row)
            print(table)
        elif "--magicbyte" in sys.argv[2]:
            try:
                mbyte=sys.argv[3]
                data=magic_scan(pcap,mbyte)
                from prettytable import PrettyTable
                table=PrettyTable()
                table.field_names=["Packet No.","Source IP","Destination IP","Packet Data with port","Source Port","Destination Port"]
                for row in data:
                    table.add_row(row)
                print(table)
            except Exception as e:
                print(str(e))
                listActions()
                exit()
            print(mbyte)
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
