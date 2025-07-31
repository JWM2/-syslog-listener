#!/usr/bin/env python3
"""Dual‑protocol syslog listener → calls get‑and‑quarantine API."""

import asyncio, socket, re, requests
from collections import deque

API_URL   = "http://159.203.46.30:8000/get-and-quarantine"
TIMEOUT_S = 5
BUFFER    = deque(maxlen=100)

LOG_FIELD_RE = re.compile(r'log="([^"]+)"')

def process_line(raw: str) -> None:
    match = LOG_FIELD_RE.search(raw)
    if not match:
        return
    kv = {}
    for part in match.group(1).split():
        if '=' in part:
            k, v = part.split('=', 1)
            kv[k] = v.strip('"')
    deviceid = kv.get('devid') or kv.get('devname')
    ip       = kv.get('srcip')
    srcintf  = kv.get('srcintf')
    if not (deviceid and ip and srcintf):
        return
    payload = {'deviceid': deviceid, 'source_interface': srcintf, 'ip': ip}
    try:
        r = requests.post(API_URL, json=payload, timeout=TIMEOUT_S)
        r.raise_for_status()
        print(f"[quarantine] OK    → {payload}")
    except Exception as exc:
        print(f"[quarantine] ERROR → {exc} :: {payload}")

async def udp_server(host='0.0.0.0', port=514):
    print(f"[syslog] UDP server on {host}:{port}")
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.setblocking(False)
    while True:
        data, addr = await loop.sock_recvfrom(sock, 8192)
        line = data.decode(errors='replace').rstrip()
        print(f"[udp] {addr[0]} → {line}")
        BUFFER.append(line)
        process_line(line)

async def tcp_server(host='0.0.0.0', port=514):
    print(f"[syslog] TCP server on {host}:{port}")
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')[0]
        while chunk := await reader.readline():
            line = chunk.decode(errors='replace').rstrip()
            print(f"[tcp] {addr} → {line}")
            BUFFER.append(line)
            process_line(line)
    server = await asyncio.start_server(handle, host, port)
    async with server:
        await server.serve_forever()

async def main():
    await asyncio.gather(udp_server(), tcp_server())

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('Shutting down.')
