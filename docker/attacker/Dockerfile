# Disposable attacker box for driving tools against a range. Attaches to the range
# network via the generated compose file's `attacker` service (profile: attacker).
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        curl \
        ldap-utils \
        dnsutils \
        smbclient \
        netcat-openbsd \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
