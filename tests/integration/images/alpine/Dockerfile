# Real OpenSSH server with BusyBox ash: stands in for routers/NAS/embedded Linux hosts.
FROM alpine:3.20

RUN apk add --no-cache openssh-server openssh-sftp-server \
    && adduser -D -s /bin/sh tester \
    && echo 'tester:testpass' | chpasswd \
    && ssh-keygen -A \
    && sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
