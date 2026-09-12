"""Sandbox-local TCP to host-owned Unix-socket relay for the fixed provider bridge."""
import os
from pathlib import Path
import select
import socket
import socketserver
import subprocess
import sys
import threading

LISTEN = ('127.0.0.1', 8765)


class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            upstream.connect(self.server.socket_path)
            peers = (self.request, upstream)
            while True:
                readable, _, _ = select.select(peers, (), (), 5)
                if not readable:
                    continue
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    target = upstream if source is self.request else self.request
                    target.sendall(data)
        finally:
            upstream.close()


class RelayServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, socket_path):
        self.socket_path = str(socket_path)
        super().__init__(LISTEN, RelayHandler)


def main(argv):
    if len(argv) < 4 or argv[2] != '--':
        raise SystemExit('usage: bridge_proxy.py /bridge/provider.sock -- command [args...]')
    socket_path = Path(argv[1])
    if not socket_path.is_socket():
        raise SystemExit('provider bridge socket is unavailable')
    server = RelayServer(socket_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    process = subprocess.Popen(argv[3:])
    try:
        return process.wait()
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
