import sys
import socket
import os
import subprocess
import logging
from copy import copy, deepcopy
from src.utils import *


addr_dict = {'www.google.com':
                 {'A': Address('192.168.43.196'), 'AAAA': Address('::1', ipv=6)},
             'google.com':
                 {'A': Address('192.168.43.196'), 'AAAA': Address('::1', ipv=6)},
             'www.baidu.com':
                 {'A': Address('192.168.43.196'), 'AAAA': Address('::1', ipv=6)},
             'www.test.com':
                 {'A': Address('192.168.43.196'), 'AAAA': Address('::1', ipv=6)},
             'www.test1.com':
                 {'A': Address('192.168.43.196'), 'AAAA': Address('::1', ipv=6)}}


def main():
    # os.system('netsh interface ip set dns name="WLAN" source=static addr=127.0.0.1 register=primary')
    while True:
        subprocess.run('ipconfig /flushdns',
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.STDOUT)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 53))
        try:
            try:
                query_data = sock.recvfrom(2048)
            except ConnectionResetError:
                logging.warning(ConnectionResetError)
                continue
            query = Query(query_data[0])
            print()
            print('原始', query_data)
            print('请求', query.encode())
            # print(query.questions[0][1], Query.QTYPE_A, Query.QTYPE_AAAA)
            if query.questions[0][0] in addr_dict:
                response = copy(query)
                response.ANCOUNT = 1
                response.QR = '1'  # Response
                response.AA = '1'  # not authoritative
                response.RA = '1'  # recursive not available
                response.Z = '000'
                RDATA = b'\x00'
                if query.questions[0][1] == Query.QTYPE_A:
                    RDATA = addr_dict[query.questions[0][0]]['A'].encode()
                    if RDATA == b'\x00\x00\x00\x00':
                        response.RCODE = Query.RCODE_NXDOMAIN  # intercept
                    else:
                        response.RCODE = Query.RCODE_NOERROR  # no error
                elif query.questions[0][1] == Query.QTYPE_AAAA:
                    RDATA = addr_dict[query.questions[0][0]]['AAAA'].encode()
                response_data = response.encode() + \
                                ResourceRecord(NAME=ResourceRecord.NAME_PTR,
                                               TYPE=query.questions[0][1],
                                               RDATA=RDATA).encode()
                print('ipv{{{}}} 回复'.format(query.questions[0][1]), response_data)
                print()
                ssend(sock, response_data, query_data[1])
            else:
                response_data = forward(query_data)
                print('else回复', response_data[0])
                print()
                sock.sendto(response_data[0], query_data[1])
        finally:
            # os.system('netsh interface ip set dns name="WLAN" source=dhcp')
            logging.info('reset done!')
            sock.close()


if __name__ == '__main__':
    main()
