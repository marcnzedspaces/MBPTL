FROM kalilinux/kali-rolling

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV USER=kali
ENV PASSWORD=kali

# Update and install base tools
RUN apt-get update && apt-get install -y \
    sudo \
    openssh-server \
    nmap \
    curl \
    wget \
    netcat-traditional \
    python3 \
    python3-pip \
    git \
    file \
    binutils \
    iproute2 \
    coreutils \
    bash \
    vim \
    nano \
    net-tools \
    iputils-ping \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create kali user with sudo privileges
RUN useradd -m -s /bin/bash kali && \
    echo 'kali:kali' | chpasswd && \
    usermod -aG sudo kali && \
    echo 'kali ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Switch to kali user for tool installations
USER kali
WORKDIR /home/kali

# Clone dirsearch
RUN git clone https://github.com/maurosoria/dirsearch.git /home/kali/tools/dirsearch && \
    cd /home/kali/tools/dirsearch && \
    pip3 install -r requirements.txt --break-system-packages

# Clone sqlmap
RUN git clone https://github.com/sqlmapproject/sqlmap.git /home/kali/tools/sqlmap

# Install pwntools
RUN pip3 install pwntools --break-system-packages

# Create workspace directories
RUN mkdir -p /home/kali/workspace /home/kali/tools /home/kali/scripts

# Create helper script for LinPEAS download
RUN echo '#!/bin/bash' > /home/kali/tools/get-linpeas.sh && \
    echo 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /home/kali/tools/linpeas.sh' >> /home/kali/tools/get-linpeas.sh && \
    echo 'chmod +x /home/kali/tools/linpeas.sh' >> /home/kali/tools/get-linpeas.sh && \
    chmod +x /home/kali/tools/get-linpeas.sh

# Create a welcome message with tool locations
RUN echo '#!/bin/bash' > /home/kali/.welcome.sh && \
    echo 'echo "================================================"' >> /home/kali/.welcome.sh && \
    echo 'echo "  Welcome to MBPTL Kali Linux Attack Box"' >> /home/kali/.welcome.sh && \
    echo 'echo "================================================"' >> /home/kali/.welcome.sh && \
    echo 'echo ""' >> /home/kali/.welcome.sh && \
    echo 'echo "Tools installed and ready:"' >> /home/kali/.welcome.sh && \
    echo 'echo "  - nmap: Port scanning"' >> /home/kali/.welcome.sh && \
    echo 'echo "  - curl/wget: HTTP requests"' >> /home/kali/.welcome.sh && \
    echo 'echo "  - netcat (nc): Network connections"' >> /home/kali/.welcome.sh && \
    echo 'echo "  - python3 + pip3: Scripting"' >> /home/kali/.welcome.sh && \
    echo 'echo "  - pwntools: Binary exploitation"' >> /home/kali/.welcome.sh && \
    echo 'echo ""' >> /home/kali/.welcome.sh && \
    echo 'echo "Tool repositories (in ~/tools/):"' >> /home/kali/.welcome.sh && \
    echo 'echo "  - dirsearch: ~/tools/dirsearch/dirsearch.py"' >> /home/kali/.welcome.sh && \
    echo 'echo "  - sqlmap: ~/tools/sqlmap/sqlmap.py"' >> /home/kali/.welcome.sh && \
    echo 'echo ""' >> /home/kali/.welcome.sh && \
    echo 'echo "To download LinPEAS: ~/tools/get-linpeas.sh"' >> /home/kali/.welcome.sh && \
    echo 'echo ""' >> /home/kali/.welcome.sh && \
    echo 'echo "Target containers:"' >> /home/kali/.welcome.sh && \
    echo 'echo "  - mbptl-main (ports 80, 8080)"' >> /home/kali/.welcome.sh && \
    echo 'echo "  - mbptl-internal (port 31337)"' >> /home/kali/.welcome.sh && \
    echo 'echo "  - mbptl-app (port 5000)"' >> /home/kali/.welcome.sh && \
    echo 'echo ""' >> /home/kali/.welcome.sh && \
    echo 'echo "Workspace: ~/workspace/"' >> /home/kali/.welcome.sh && \
    echo 'echo "================================================"' >> /home/kali/.welcome.sh && \
    echo 'echo ""' >> /home/kali/.welcome.sh && \
    chmod +x /home/kali/.welcome.sh

# Add welcome message to bashrc
RUN echo '' >> /home/kali/.bashrc && \
    echo '# Display welcome message' >> /home/kali/.bashrc && \
    echo 'if [ -f ~/.welcome.sh ]; then' >> /home/kali/.bashrc && \
    echo '    ~/.welcome.sh' >> /home/kali/.bashrc && \
    echo 'fi' >> /home/kali/.bashrc && \
    echo '' >> /home/kali/.bashrc && \
    echo '# Useful aliases' >> /home/kali/.bashrc && \
    echo 'alias dirsearch="python3 ~/tools/dirsearch/dirsearch.py"' >> /home/kali/.bashrc && \
    echo 'alias sqlmap="python3 ~/tools/sqlmap/sqlmap.py"' >> /home/kali/.bashrc && \
    echo 'alias ll="ls -lah"' >> /home/kali/.bashrc && \
    echo 'alias tools="cd ~/tools"' >> /home/kali/.bashrc && \
    echo 'alias workspace="cd ~/workspace"' >> /home/kali/.bashrc

# Switch back to root for service setup
USER root

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Fix nmap permissions for non-root users
RUN chmod u+s /usr/bin/nmap || true

# Create startup script
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'service ssh start' >> /start.sh && \
    echo 'su - kali' >> /start.sh && \
    chmod +x /start.sh

# Set working directory
WORKDIR /home/kali/workspace

# Keep container running
CMD ["/bin/bash", "-c", "service ssh start && tail -f /dev/null"]
