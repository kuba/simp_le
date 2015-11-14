#!/bin/sh -xe

bootstrap_deb () {
  apt-get update

  install () {
    apt-get install -y --no-install-recommends "$@"
  }

  install \
    ca-certificates \
    gcc \
    libssl-dev \
    libffi-dev \
    python \
    python-dev \
    python-virtualenv

  # virtualenv binary can be found in different packages depending on
  # distro version
  install virtualenv || true
}

bootstrap_rpm () {
  installer=$(command -v dnf || command -v yum)
  "${installer?}" install -y \
    ca-certificates \
    gcc \
    libffi-devel \
    openssl-devel \
    python \
    python-devel \
    python-virtualenv
}

if [ -f /etc/debian_version ]
then
  bootstrap_deb
elif [ -f /etc/redhat-release ]
then
  bootstrap_rpm
fi
