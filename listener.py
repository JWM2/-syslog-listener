#!/usr/bin/env python3
"""
Dual-protocol syslog listener → calls get-and-quarantine API.

• Listens on UDP *and* TCP 514 (run container with --net=host).
• Parses FortiAnalyzer IPS alerts, even when the log="..." segment
  contains back-slash-escaped quotes (\").
• POSTs JSON {"deviceid", "source_interface", "ip"} to the middleware API.
• Print-only, designed to run with `python -u` so every line appears
  immediately (no stdout buffering).
"""

import asyncio, socket, re, requests
from collections import deque

API_URL   = "http://159.203.46.30:8000/get-and-quarantine"   # adjust if needed
TIMEOUT_S = 5
BUFFER    = deque(maxlen=100)

# ── Regex that tolerates escaped quotes inside log="…"
LOG_FIELD_RE = re.compile(r'log="((?:[^"\\]|\\.)*)"')

def process_line(raw: str) -> None:
    m = LOG_FIELD_RE.search(raw)
    if not m:
        return

    # Un-escape any \" inside the captured string
    kv_string = m.group(1).replace(r'\"', '"')

    # Split key=value pairs into a dict
    kv = {}
    for part in kv_string.split():
        if '=' in part:
            k, v = part.split('=', 1)
            kv[k] = v.strip('"')

    deviceid = kv.get('devid') or kv.get('devname')
    ip       = kv.get('srcip')
    srcintf  = kv.get('srcintf')

    if not (deviceid and ip and srcintf):
        return   # required fields not present

    payload = {
        'deviceid': deviceid,
        'source_interface': srcintf,
        'ip': ip
    }

    try:
        r = requests.post(API_URL, json=payload, timeout=TIMEOUT_S)
        r.raise_for_status()
        print(f"[quarantine] OK    → {payload}")
    except Exception as exc:
        print(f"[quarantine] ERROR → {exc} :: {payload}")

# ── Async servers ────────────────────────────────────────────────────────────
async def udp_server(host='0.0.0.0', port=514):
    print(f"[syslog] UDP server on {host}:{port}")
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port)); sock.setblocking(False)
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

# ── Entrypoint ───────────────────────────────────────────────────────────────
async def main():
    await asyncio.gather(udp_server(), tcp_server())

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shutting down.")
