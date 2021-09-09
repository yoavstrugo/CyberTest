import sys
from scapy.all import *
import re
from time import time
_IP_REGEX = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'


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

    # Build the packet
    # No need to add Ether() at start because we are sending normally, in 3rd-layer
    # type=8 in ICMP means 'Echo Request', this is the ping type
    request = IP(dst=host) / ICMP(type=8) / ('a' * 32)

    # Send the packet and wait for the reply
    print(f'Sending 32 bytes of data to {host}.')

    response_time = time()  # Record the current time, before sending the request
    reply = sr1(request, verbose=False)
    response_time = time() - response_time  # Subtract the response_time time to get the round-trip time

    # Print the response time
    print(f'Got response from {host} in {int(response_time * 1000)}ms.')


if __name__ == '__main__':
    main()
