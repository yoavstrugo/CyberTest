import sys
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR

_DNS_SERVER = '1.1.1.1'
_TIME_OUT = 2

def main():
    # Validate the positional args
    if len(sys.argv) < 2:
        print('Missing hostname.')
        return
    elif len(sys.argv) > 2:
        print('Too many positional arguments.')
        return

    host = sys.argv[1]

    # DNS is on top of UDP
    # rd=1 (rr for Recursive Desired), use recursive to find the domain
    # qtype=1 for type A, a host address
    dns_packet = IP(dst=_DNS_SERVER) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=host, qtype=1))

    reply = sr1(dns_packet, timeout=_TIME_OUT)

    if reply is None:
        print('Request timed out.')
        return

    print(f'The IP of host \'{host}\' is \'{reply[DNS].an.rdata}\'.')

if __name__ == '__main__':
    main()
