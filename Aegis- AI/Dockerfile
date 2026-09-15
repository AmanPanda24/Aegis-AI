FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p data models logs config

# Run as an unprivileged user. Live packet capture (raw sockets) needs
# CAP_NET_RAW/CAP_NET_ADMIN; grant that capability explicitly at `docker run`
# time (--cap-add=NET_RAW --cap-add=NET_ADMIN) instead of running the whole
# container as root, which was the previous default and gave the process
# far more privilege than packet capture actually requires.
RUN groupadd -r aegis && useradd -r -g aegis -d /app aegis \
    && chown -R aegis:aegis /app
USER aegis

# The API key is read from AEGIS_API_KEY at runtime (src/core/auth.py) -
# intentionally NOT set here, since anything set in a Dockerfile ENV is
# baked into the image layer and visible to anyone with the image.
# Pass it at run time instead, e.g.:
#   docker run -e AEGIS_API_KEY=$(openssl rand -hex 32) ...

EXPOSE 8000

CMD ["python", "src/api/main.py"]
