How to rebuild & deploy

cd /opt/syslog-listener
docker compose down          # stop old if needed
docker compose up -d --build # rebuild & start

Attach to watch:

docker attach --sig-proxy=false --detach-keys="ctrl-x" syslog-listener


# syslog-listener

Dual-protocol (UDP + TCP) Syslog receiver that parses FortiAnalyzer IPS alerts
and auto-quarantines matching hosts via an internal API.

                 FAZ  ➜  this container  ➜  FastAPI middleware
                 (514)                   (POST /get-and-quarantine)




---

## Features

* **UDP + TCP 514** on host network – no NAT / port-mapping headaches.
* Extracts `devid|devname`, `srcip`, `srcintf` from `log="…"` segment.
* Calls `http://159.203.46.30:8000/get-and-quarantine` with JSON:

  ```json
  {
    "deviceid": "FG100FTK23017292",
    "source_interface": "port5",
    "ip": "10.10.20.203"
  }


Prints [quarantine] OK / ERROR so you know every action’s outcome.

Runs un-buffered (python -u) and with --log-driver=none
→ zero disk log growth (use docker attach for live view).


Quick start

# build & run (host networking, auto-restart, no disk logs)
docker compose up -d --build

# watch live syslog + quarantine output
docker attach --sig-proxy=false --detach-keys="ctrl-x" syslog-listener
# press Ctrl-X to detach without stopping


File	Purpose
listener.py	Core asyncio server + FortiAnalyzer parser + API call
Dockerfile	Builds a slim Python 3.12 image and installs requests
docker-compose.yml	Runs the service with host network, auto-restart, no logs
.dockerignore	Keeps editor / OS junk out of the image
README.md	This guide

Testing
Send a manual packet from your workstation

Updating
Edit listener.py (e.g., tweak regex or API URL).

Rebuild & restart:

docker compose up -d --build

