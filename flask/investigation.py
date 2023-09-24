from scapy.utils import RawPcapReader
from magic_headers import magic_list
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP,IP 


def magic_bytes_find_all(pcap):
    data_structure={}

    magic_lists=magic_list()
    for (packets,metadata) in RawPcapReader(pcap):
        hexPacket=''.join([format(byte, '02x') for byte in packets])
        for each_magic in magic_lists:
            x=str(each_magic[1]).replace(" ","").lower() #this is magic byte
            y=str(each_magic[0]) #this is value of magic byte like WIndows PE or Zip file
            if x in str(hexPacket):
                if y in data_structure:
                    data_structure[y]["number"]+=1
                else:
                    data_structure[y]={"number":1}
                   
    return data_structure


def file_scan(pcap):
    count=0
    magicbytes=magic_list()
    finalData=[]
    for (packets,metadata) in RawPcapReader(pcap):
        count+=1                  
        hexPacket=''.join([format(byte, '02x') for byte in packets])
        for each_magic in magicbytes:
            x=str(each_magic[1]).replace(" ","").lower() #this is magic byte
            y=str(each_magic[0]) #this is value of magic byte like WIndows PE or Zip file
            if x in str(hexPacket):
                block=[y,x,count,
                       str(Ether(packets)[IP].src),
                       str(Ether(packets)[IP].dst),
                      str(Ether(packets)[IP]),
                       Ether(packets)[IP].sport,
                        Ether(packets)[IP].dport]
                #[File name, File magic byte, source IP, Destination IP, TCP Communication for better understanding, Source Port, Destination Port]
                finalData.append(block)
    return finalData