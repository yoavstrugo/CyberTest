import sys
import re
from time import time
from scapy.all import *

_IP_REGEX = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

# The number of pings per hop
_PINGS_PER_HOP = 3

# The maximum number of hops
_MAXIMUM_HOPS = 30

_TIMEOUT = 2


def main():
    # Validate the positional args
    if len(sys.argv) < 2:
        print('Missing host ip.')
        return
    elif len(sys.argv) > 2:
        print('Too many positional arguments.')
        return

    host = sys.argv[1]
    # Validate the ip format
    if not re.match(_IP_REGEX, host):
        print('IP is invalid format.')
        return

    print(f'Tracing route to {host}:')

    for i in range(1, _MAXIMUM_HOPS):
        # A request packet
        trace_packet = IP(dst=host, ttl=i) / ICMP(type=8) / ('a' * 32)

        has_responded = False
        responder_ip = None
        arrived = False

        print(i, end='\t')
        for j in range(_PINGS_PER_HOP):
            # Calculate the response time
            response_time = time.time()
            reply = sr1(trace_packet, verbose=False, timeout=_TIMEOUT)
            response_time = time.time() - response_time

            # type=3 means Destination unreachable
            if reply is None or reply[ICMP].type == 3:
                print('*', end='\t\t')
                continue
            # type=0 means reply, it's the final station
            elif reply[ICMP].type == 0:
                arrived = True

            # TTL exceeded
            has_responded = True
            responder_ip = reply[IP].src
            print(f'{int(response_time * 1000)}ms', end='\t\t')

        if has_responded:
            print(responder_ip)
            # Reached the host
            if arrived:
                return
        else:
            print('Request timed out.')


if __name__ == '__main__':
    main()
