import socket
from dns import fake_bmsg, parse_msg, DNSHeader, DNSQuestion
from utils import cprint, cprint_header, cprint_question
from utils import bytes_to_int
import multiprocessing as mp
from multiprocessing import Manager
from datetime import datetime
import time
import os.path as osp


def forward(msg):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    real_dns_server = ('223.5.5.5', 53)  # ali dns server
    sock.sendto(msg, real_dns_server)
    answer, _ = sock.recvfrom(1024)
    return answer


def relay(queue: mp.Queue, bmsg: bytes, addr: tuple, relay_dict, recv_time: datetime):
    cprint(f'[recv query {bytes_to_int(bmsg[:2])}]: {bmsg} from {addr}', fore='green', style='reverse')
    bmsg = bytearray(bmsg)
    header = DNSHeader(bmsg[:12])
    header.aa = 1
    bmsg = header.bmsg + bmsg[12:]
    cprint_header(header, fore='green')
    assert header.qdcount == 1
    question = DNSQuestion(bmsg, offset=12)
    cprint_question(question, fore='green')
    # cprint('\t', question.qname, question.qname in relay_dict, fore='green')
    mode = 'relay msg  '
    if question.qname in relay_dict:
        if relay_dict[question.qname] == '0.0.0.0':
            header.rcode = 3
            answer = header.bmsg + bmsg[12:]
            mode = 'intercept  '
            # cprint(f'[intercept  {bytes_to_int(answer[:2])}]: {answer}', fore='cyan', style='reverse')
        elif question.qtype == 1:
            answer = fake_bmsg(bmsg, relay_dict[question.qname])
            mode = 'local resolve '
            # cprint(f'[local resolve {bytes_to_int(answer[:2])}]: {answer}', fore='cyan', style='reverse')
        else:
            answer = forward(bmsg)
            mode = 'relay msg  '
            # cprint(f'[relay msg  {bytes_to_int(answer[:2])}]: {answer}', fore='cyan', style='reverse')
    else:
        answer = forward(bmsg)
        mode = 'relay msg  '
        # cprint(f'[relay msg  {bytes_to_int(answer[:2])}]: {answer}', fore='cyan', style='reverse')

    # answer = parse_msg(answer, fore='cyan')
    queue.put((answer, addr, recv_time, mode))


def receiver(queue, lock, relay_dict):
    config_path = osp.join(osp.dirname(__file__), 'etc', 'config')
    last_read_config_time = osp.getmtime(config_path)
    while True:
        with lock:
            if osp.getmtime(config_path) > last_read_config_time:
                last_read_config_time = osp.getmtime(config_path)
                config_file = open('etc/config')
                relay_dict = {}
                for line in config_file:
                    addr, name = line.strip('\n').split(' ')
                    relay_dict[name] = addr
                print(relay_dict)
                config_file.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind(('127.0.0.1', 53))
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(0.1)
                bmsg, addr = sock.recvfrom(1024)
                mp.Process(target=relay, args=(queue, bmsg, addr, relay_dict, datetime.now())).start()
            except socket.timeout:
                ...
            finally:
                sock.close()


def backsender(queue, lock):
    while True:
        with lock:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind(('127.0.0.1', 53))
                # for answer_count in range(int(queue.qsize() / 2 + 1)):
                for answer_count in range(queue.qsize()):
                    if queue.qsize() <= 0:
                        break
                    answer, addr, recv_time, mode = queue.get()
                    cprint(f'[{mode}{bytes_to_int(answer[:2])}]: {answer}', fore='cyan', style='reverse')
                    answer = parse_msg(answer, fore='cyan')
                    sock.sendto(answer, addr)
                    time_cost = datetime.now() - recv_time
                    cprint(f'[time cost  {bytes_to_int(answer[:2])}]: {time_cost}', fore='blue', style='reverse')
            finally:
                sock.close()


def main():
    with Manager() as manager:
        relay_dict = manager.dict()
        config_file = open('etc/config')
        for line in config_file:
            addr, name = line.strip('\n').split(' ')
            relay_dict[name] = addr
        print(relay_dict)
        queue = mp.Queue()
        socket_lock = mp.Lock()
        receiver_process = mp.Process(target=receiver, args=(queue, socket_lock, relay_dict))
        backsender_process = mp.Process(target=backsender, args=(queue, socket_lock))
        receiver_process.start()
        backsender_process.start()
        receiver_process.join()
        backsender_process.join()
        receiver_process.close()
        backsender_process.close()


if __name__ == '__main__':
    main()
