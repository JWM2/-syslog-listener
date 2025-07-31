FROM python:3.12-slim

RUN pip install --no-cache-dir requests

WORKDIR /app
COPY listener.py .

EXPOSE 514/udp
EXPOSE 514/tcp

CMD ["python", "listener.py"]
