ARG BASE_IMAGE=debian:12-slim
FROM ${BASE_IMAGE}

ENV container=docker
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      coreutils \
      curl \
      dbus \
      iproute2 \
      jq \
      procps \
      systemd \
      systemd-sysv \
      tar \
      util-linux \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
