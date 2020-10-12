import logging
import socket


def bytes_to_binary(x):
    return ''.join(['{:08d}'.format(int(bin(i)[2:])) for i in x])


class CLASSES:
    IN = 1
    CS = 2
    CH = 3
    HS = 4


class Query:
    RCODE_NOERROR = '0000'
    RCODE_NXDOMAIN = '0011'
    QTYPE_A = '{:016d}'.format(int(bin(1)[2:]))
    QTYPE_AAAA = '{:016d}'.format(int(bin(28)[2:]))

    def __init__(self, _bytes):
        self._bytes = _bytes
        # Header Section
        binary = bytes_to_binary(_bytes[:12])
        self.ID = binary[0:16]
        self.QR = binary[16]
        self.Opcode = binary[17:21]
        self.AA = binary[21]
        self.TC = binary[22]
        self.RD = binary[23]
        self.RA = binary[24]
        self.Z = binary[25:28]
        self.RCODE = binary[28:32]
        self.QDCOUNT = int(binary[32:48], 2)
        self.ANCOUNT = int(binary[48:64], 2)
        self.NSCOUNT = int(binary[64:80], 2)
        self.ARCOUNT = int(binary[80:96], 2)

        # Question Section
        self.questions = []
        cur = 0
        _bytes = _bytes[12:]
        for entry_count in range(self.QDCOUNT):
            question, _bytes = Query.parse_question_section(_bytes)
            self.questions.append(question)

        # Answer Section
        # Authority Section
        # Additional Section

    def encode(self):
        id_flags = int((self.QR + self.Opcode + self.AA + self.TC +
                        self.RD + self.RA + self.Z + self.RCODE), 2)
        return self._bytes[:2] + id_flags.to_bytes(2, 'big') + \
               self.QDCOUNT.to_bytes(2, 'big') + \
               self.ANCOUNT.to_bytes(2, 'big') + \
               self.NSCOUNT.to_bytes(2, 'big') + \
               self.ARCOUNT.to_bytes(2, 'big') + \
               self._bytes[12:]

    @staticmethod
    def parse_question_section(_bytes):
        cur = 0
        QNAME = []
        while True:
            label_len = int(_bytes[cur])
            if label_len == 0:
                break
            QNAME.append(_bytes[cur + 1: cur + label_len + 1].decode())
            cur += label_len + 1
        cur += 1
        QTYPE = bytes_to_binary(_bytes[cur: cur + 2])
        QCLASS = bytes_to_binary(_bytes[cur + 2: cur + 4])
        cur += 4
        return ('.'.join(QNAME), QTYPE, QCLASS), _bytes[cur:]


class ResourceRecord:
    NAME_PTR = 0
    QTYPE_A = 1
    QTYPE_AAAA = 28

    def __init__(self, NAME=None, TYPE=1, CLASS=1, TTL=60, RDATA=None):
        if not NAME:
            self.NAME = b'\xc0\x0c'  # pointer referring to `\x0c`(i.e. first QNAME)
        elif NAME == ResourceRecord.NAME_PTR:
            self.NAME = b'\xc0\x0c'  # pointer referring to `\x0c`(i.e. first QNAME)
        elif type(NAME) == DomainName:
            self.NAME = NAME.encode()
        else:
            assert (type(NAME) == bytes)
            self.NAME = NAME  # domain name

        self.TYPE = TYPE  # 16 bits
        self.CLASS = CLASS  # 16 bits
        self.TTL = TTL  # 32 bits
        if not RDATA:
            self.RDATA = bytes()
        elif type(RDATA) == Address:
            self.RDATA = RDATA.encode()
        else:
            assert (type(RDATA) == bytes)
            self.RDATA = RDATA  # variable
        self.RDLENGTH = len(self.RDATA)  # 16 bits

    def encode(self):
        return self.NAME + \
               self.TYPE.to_bytes(2, 'big') + \
               self.CLASS.to_bytes(2, 'big') + \
               self.TTL.to_bytes(4, 'big') + \
               self.RDLENGTH.to_bytes(2, 'big') + \
               self.RDATA


class DomainName:
    def __init__(self, domain_name):
        self.domain_name = None
        if type(domain_name) == str:
            self.domain_name = domain_name.split('.')
        elif type(domain_name) == list or type(domain_name) == tuple:
            self.domain_name = domain_name

    def encode(self):
        code = []
        for label in self.domain_name:
            code.append(len(label).to_bytes(1, 'big'))
            code.append(label.encode())
        return b''.join(code + [b'\x00'])


class Address:
    def __init__(self, address, ipv=4):
        self.address = None
        if ipv == 4:
            self.ipv = 4
            if type(address) == str:
                self.address = address.split('.')
            elif type(address) == list or type(address) == tuple:
                self.address = address
            try:
                self.address = [int(i) for i in self.address]
            except ValueError:
                logging.warning('invalid address format')
            if len(self.address) != 4:
                raise ValueError
            for i in self.address:
                if not 0 <= i < 256:
                    raise ValueError
        elif ipv == 6:
            self.ipv = 6
            print(address)
            zeros_index = address.find('::')
            if zeros_index != -1:
                address = address[:zeros_index] + ':' + '0:' * (8-address.count(':')) + address[zeros_index+2:]
                if address[0] == ':':
                    address = '0' + address
                elif address[-1] == ':':
                    address = address + '0'
            if type(address) == str:
                self.address = address.split(':')
            elif type(address) == list or type(address) == tuple:
                self.address = address
            print(self.address)
            try:
                self.address = [int(i, 16) for i in self.address]
            except ValueError:
                logging.warning('invalid address format')
            for i in self.address:
                if not 0 <= i < 65536:
                    raise ValueError

    def encode(self):
        code = []
        for i in self.address:
            if self.ipv == 4:
                code.append(i.to_bytes(1, byteorder='big'))
            elif self.ipv == 6:
                code.append(i.to_bytes(2, byteorder='big'))
        return b''.join(code)


def forward(data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(data[0], ('8.8.8.8', 53))
    try:
        recv = sock.recvfrom(2048)
    finally:
        sock.close()
    return recv[0], data[1]


if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 53))
    try:
        while True:
            data = forward(sock.recvfrom(2048))
            sock.sendto(data[0], data[1])
    finally:
        sock.close()