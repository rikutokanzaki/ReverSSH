FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server bash python3 python-is-python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /root/.ssh /tmp/reverssh-tab-target /tmp/reverssh-replay \
    && touch /root/e2e-marker

RUN echo 'root:test-password' | chpasswd \
    && printf '%s\n' \
       'PermitRootLogin yes' \
       'PasswordAuthentication yes' \
       'UsePAM no' \
       'PrintMotd no' \
       'PermitEmptyPasswords no' \
       >> /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
