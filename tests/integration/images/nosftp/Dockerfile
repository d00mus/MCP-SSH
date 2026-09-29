# Debian sshd without the sftp subsystem: makes the file tool fall back to shell commands.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server bash procps coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && useradd -m -s /bin/bash tester \
    && echo 'tester:testpass' | chpasswd \
    && ssh-keygen -A \
    && sed -i '/^Subsystem/d' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
