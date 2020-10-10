import sys
import socket
import os
import subprocess
import logging
from copy import copy, deepcopy
from src.utils import *

def main():
    # os.system('netsh interface ip set dns name="WLAN" source=static addr=127.0.0.1 register=primary')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 53))
    try:
        while True:
            subprocess.run('ipconfig /flushdns',
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.STDOUT)
            data = sock.recvfrom(2048)
            query = Query(data[0])
            dictionary = {'www.google.com': [182, 61, 200, 7]}
            if query.questions[0][0] in dictionary:
                print()
                print('原始', data)
                print('请求', query.encode())
                response = copy(query)
                response.ANCOUNT = 1
                response.QR = '1'  # Response
                response.AA = '0'  # not authoritative
                response.RA = '1'  # recursive not available
                response.Z = '000'
                response.RCODE = '0000'  # no error
                print('回复', response.encode() +
                      Answer(NAME=bytes([192, 12]), RDATA=bytes(dictionary[query.questions[0][0]])).encode())
                print()
                sock.sendto(response.encode() + Answer(NAME=bytes([192, 12]),
                                                       RDATA=bytes(dictionary[query.questions[0][0]])).encode(),
                            data[1])
                # network.dnsCacheExpirationGracePeriod
                # network.dns.forceResolve
                # network.dns.ipv4OnlyDomains
                # network.dns.localDomains
    finally:
        # os.system('netsh interface ip set dns name="WLAN" source=dhcp')
        logging.info('reset done!')
        sock.close()


if __name__ == '__main__':
    main()
