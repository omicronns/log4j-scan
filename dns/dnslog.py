import socket
import sys
import re
import binascii
from dnslib import DNSRecord

UDP_IP = "0.0.0.0"
UDP_PORT = 53

with open(sys.argv[1], "a") as log:
    print('dns logger started...', file=log)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:
    byteData, addr = sock.recvfrom(2048)
    try:
        msg = binascii.unhexlify(binascii.b2a_hex(byteData))
        pkt = DNSRecord.parse(msg)
        with open(sys.argv[1], "a") as log:
            print('question: {}'.format(pkt.get_q().get_qname()), file=log)
    except Exception as e:
        print(e)
        continue
