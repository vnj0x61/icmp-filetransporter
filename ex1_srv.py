#!/usr/bin/python3
# icmp-textfile-recv

# import modules
from scapy.all import *
import base64

# function to extract contents from icmp
def workitout(packet):
# UNCOMMENT FOR DEBUG
    #print(packet)
    #print("function " + str(packet.load))
    try:
        if str(packet.getlayer(ICMP).type) == "8":
# get payload from ICMP packet
            output = packet.load
# UNCOMMENT FOR DEBUG
            #print(output)
            #print(type(output))
# decode payload from base64
            data_bytes = base64.b64decode(output)
            data = data_bytes.decode('utf-8')
# UNCOMMENT FOR DEBUG
            #print(data)
# split decoded payload to Parts: filename, segmentnumber/bytenumber, content
            file_data = data.split("_", 3) # change later to 3
# print segmentnumber/bytenumber
            print(file_data[1])
# check if first segment from transfer
            if int(file_data[1]) == 0:
# open file for writing, if not exist create, if exist ovwerwrite
                with open(file_data[0], "w") as f:
                    f.write(file_data[2])
# check if segment ist not the first and append content to created file                    
            elif int(file_data[1]) > 0:
                with open(file_data[0], "a") as f:
                    f.write(file_data[2])
                    
# catch errors like other or normal pings
    except:
        pseudo = 0
        print("outsch!")
        
# infinity loop
while True:

    try:
# sniff for icmp packets and hand it over to function workitout
        pkts = sniff(filter="icmp", prn=workitout)
        
    except:
        print("FAILURE!")
# if STRG+C are pressed programm will only jump out if try,except
# with this we can end the programm    
    raise SystemExit
            
