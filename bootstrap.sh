#!/bin/sh -xe

# keep in sync with .travis.yml
bootstrap_deb () {
  apt-get update

  install () {
    apt-get install -y --no-install-recommends "$@"
  }

  # virtualenv binary can be found in different packages depending on
  # distro version
  package="python-virtualenv"

  if ! apt-cache show -qq "${package}" > /dev/null 2>&1
  then
  	package="virtualenv"
  fi

  install \
    ca-certificates \
    gcc \
    libssl-dev \
    libffi-dev \
    python \
    python-dev \
    "${package}"
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
