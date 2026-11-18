FROM oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61 AS bun
FROM tailscale/tailscale:v1.86.2@sha256:241d9518b7e0b6e533dbd0117fcea15acb4174249210837f52b71615949ce9d2 AS tailscale

FROM ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8 AS scanner
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nmap

FROM scanner AS live
COPY --from=tailscale /usr/local/bin/tailscale /usr/local/bin/tailscale
COPY --from=tailscale /usr/local/bin/tailscaled /usr/local/bin/tailscaled
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-client ca-certificates

FROM scanner AS vps
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
     nftables iproute2 unattended-upgrades docker.io
