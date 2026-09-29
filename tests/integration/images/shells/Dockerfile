# Real OpenSSH server with one account per login shell: what the gateway meets on hosts
# that do not give a bash/sh login (zsh, fish, tcsh).
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server bash zsh fish tcsh dash procps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && for shell in bash zsh fish tcsh dash; do \
         useradd -m -s "$(command -v $shell)" "user_$shell" \
         && echo "user_$shell:testpass" | chpasswd; \
       done \
    && useradd -m -s /bin/bash tester \
    && echo 'tester:testpass' | chpasswd \
    && ssh-keygen -A

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
