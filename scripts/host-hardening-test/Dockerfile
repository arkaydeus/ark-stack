FROM oven/bun:1.4.4-slim@sha256:1846adf22496bd711036aae8be147e57bdebbaea2e5264e3e0b5af1db187d9a4 AS bun
FROM tailscale/tailscale:v1.86.2@sha256:241d9518b7e0b6e533dbd0117fcea15acb4174249210837f52b71615949ce9d2 AS tailscale

FROM ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8 AS ubuntu
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun

FROM ubuntu AS ssh
RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
     iproute2 systemd-sysv dbus openssh-server sshpass

FROM ubuntu AS scanner
RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nmap

FROM scanner AS live
COPY --from=tailscale /usr/local/bin/tailscale /usr/local/bin/tailscale
COPY --from=tailscale /usr/local/bin/tailscaled /usr/local/bin/tailscaled
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-client ca-certificates

FROM scanner AS vps
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
     nftables iproute2 unattended-upgrades docker.io docker-compose-v2 systemd-sysv dbus dnsmasq-base openssl \
  && systemctl mask docker.service docker.socket
