from scapy.utils import RawPcapReader
from scapy.all import PcapReader
from magic_headers import magic_list
from scapy.layers.inet import *
from scapy.layers.l2 import Ether
from scapy.layers import http
from scapy.all import *
    
def magic_bytes_find_all(pcap):
    data_structure={}
    count=0
    magic_lists=magic_list()
    meta={}
    for (packets,metadata) in RawPcapReader(pcap):
        count+=1
        meta={}
        hexPacket=''.join([format(byte, '02x') for byte in packets])
        for each_magic in magic_lists:
            x=str(each_magic[1]).replace(" ","").lower() #this is magic byte
            y=str(each_magic[0]) #this is value of magic byte like WIndows PE or Zip file
            if x in str(hexPacket):
                meta["number"]=count
                meta[""]
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
    for i in finalData:
        print(i)
        


pcapfile="zip.pcap"
data=file_scan(pcapfile)
# ret=[]
# for i in data:
#     block=[i,data[i]["number"]]
#     ret.append(block)



# for d in data:
#     print(f"{d}:{data[d]}")

# for (packets,metadata) in RawPcapReader(pcapfile):
#     packet=ether(packets)
    