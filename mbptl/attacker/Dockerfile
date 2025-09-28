# attacker/Dockerfile
# Minimal, repeatable Kali-based attacker container for the MBPTL lab

# syntax=docker/dockerfile:1
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    LANG=C.UTF-8

# Core tooling (networking, web, debugging) + Python extras
RUN apt update && apt -y full-upgrade && \
    apt install -y --no-install-recommends \
      nmap ncat netcat-traditional netcat-openbsd \
      iproute2 iputils-ping dnsutils curl wget tcpdump socat \
      python3 python3-pip python3-venv \
      build-essential gcc gdb make \
      git ca-certificates openssl \
      vim nano less jq procps file \
    && pip3 install --no-cache-dir pwntools \
    # Docker often blocks setuid; nmap works fine as root without it
    && chmod u-s /usr/lib/nmap/nmap || true \
    && rm -rf /var/lib/apt/lists/*

# Quality-of-life prompt and aliases
RUN echo 'PS1="\\[\\e[0;36m\\]┌──(\\u㉿MBPTL)-[\\w]\\n└─# \\[\\e[0m\\]"' >> /root/.bashrc && \
    echo 'alias ll="ls -alF"' >> /root/.bashrc && \
    echo 'alias loot="cd /loot"' >> /root/.bashrc

# Default working dir is the shared loot folder from docker-compose
WORKDIR /loot

ENTRYPOINT ["/bin/bash"]
