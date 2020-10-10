import logging


def bytes_to_binary(x):
    return ''.join(['{:08d}'.format(int(bin(i)[2:])) for i in x])


class CLASSES:
    IN = 1
    CS = 2
    CH = 3
    HS = 4


class TYPES:
    A = 1   # a host address


class Query:
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


class Answer:
    def __init__(self, NAME=None, TYPE=1, CLASS=1, TTL=60, RDATA=None):
        if not NAME:
            NAME = bytes()
        if not RDATA:
            RDATA = bytes()
        self.NAME = NAME  # domain name
        self.TYPE = TYPE  # 16 bits
        self.CLASS = CLASS  # 16 bits
        self.TTL = TTL  # 32 bits
        self.RDLENGTH = len(RDATA)  # 16 bits
        self.RDATA = RDATA  # variable

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


if __name__ == '__main__':
    print(DomainName('www.google.com').encode())
