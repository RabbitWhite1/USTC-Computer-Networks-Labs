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
            try:
                query_data = sock.recvfrom(2048)
            except ConnectionResetError:
                continue
            query = Query(query_data[0])
            dict_ipv4 = {'www.google.com': Address('127.0.0.1'),
                         'google.com': Address('127.0.0.1'),
                         'www.baidu.com': Address('127.0.0.1'),
                         'www.test.com': Address('127.0.0.1'),
                         'www.test1.com': Address('192.168.43.196')}
            dict_ipv6 = {'www.google.com': Address('::1', ipv=6),
                         'www.baidu.com': Address('::1', ipv=6),
                         'www.test.com': Address('::1', ipv=6),
                         'www.test1.com': Address('::1', ipv=6)}
            print()
            print('here原始', query_data)
            print('here请求', query.encode())
            # print(query.questions[0][1], Query.QTYPE_A, Query.QTYPE_AAAA)
            if query.questions[0][1] == Query.QTYPE_A \
                    and query.questions[0][0] in dict_ipv4:
                response = copy(query)
                response.ANCOUNT = 1
                response.QR = '1'  # Response
                response.AA = '1'  # not authoritative
                response.RA = '1'  # recursive not available
                response.Z = '000'
                RDATA = dict_ipv4[query.questions[0][0]].encode()
                if RDATA == b'\x00\x00\x00\x00':
                    response.RCODE = Query.RCODE_NXDOMAIN  # intercept
                else:
                    response.RCODE = Query.RCODE_NOERROR  # no error
                print('RDATA', RDATA)
                print('RCODE', response.RCODE)
                response_data = response.encode() + \
                                ResourceRecord(NAME=ResourceRecord.NAME_PTR,
                                               RDATA=RDATA).encode()
                print('here4回复', response_data)
                print()
                sock.sendto(response_data, query_data[1])
            elif query.questions[0][1] == Query.QTYPE_AAAA \
                    and query.questions[0][0] in dict_ipv6:
                response = copy(query)
                response.ANCOUNT = 1
                response.QR = '1'  # Response
                response.AA = '1'  # not authoritative
                response.RA = '1'  # recursive not available
                response.Z = '000'
                RDATA = dict_ipv6[query.questions[0][0]].encode()
                print('RDATA', RDATA)
                print('RCODE', response.RCODE)
                rsrc_record = ResourceRecord(NAME=ResourceRecord.NAME_PTR,
                                             TYPE=ResourceRecord.QTYPE_AAAA,
                                             RDATA=RDATA)
                print(rsrc_record.TYPE)
                response_data = response.encode() + rsrc_record.encode()


                print('here6回复', response_data)
                print()
                sock.sendto(response_data, query_data[1])
            else:
                continue
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
