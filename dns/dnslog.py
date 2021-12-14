import socket
import sys
import re
import binascii
from dnslib import DNSRecord, RR, A

UDP_IP = "0.0.0.0"
UDP_PORT = 53

with open(sys.argv[1], "a") as log:
    print('dns logger started...', file=log)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(2048)
    try:
        pkt = DNSRecord.parse(data)
        with open(sys.argv[1], "a") as log:
            print('question: {}'.format(pkt.get_q().get_qname()), file=log)
        rsp = pkt.reply()
        rsp.add_answer(RR(pkt.get_q().get_qname(), rdata=A("127.0.0.1")))
        sock.sendto(rsp.pack(), addr)
    except Exception as e:
        print(e)
        continue
