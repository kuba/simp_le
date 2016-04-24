#!/bin/sh

# This script is sourced in .travis.yml, and `source` doesn't take
# into evaluate the shebang line, so it needs to be set explicitly
# here. Otherwise tests will happily pass despite non-zero exit codes
# from some of the commands in this file (#39).
set -xe

SERVER=http://localhost:4000/directory
PORT=5002

integration_install() {
  ./tests/boulder_setup.sh &
  ./tests/tmp_http_setup.sh &
  wait
}

integration_script() {
  . .tox/$TOXENV/bin/activate
  TESTCMD="${PWD?}/tests/integration.sh"
  cd $GOPATH/src/github.com/letsencrypt/boulder/
  python test/integration-test.py --custom "${TESTCMD?}"
}

if [ "py${TOXENV#py}" = "${TOXENV}" ]; then
  BOULDER_INTEGRATION=yes
fi

case $1 in
  before_install)
    if [ "x$BOULDER_INTEGRATION" != "x" ]; then
      eval "$(gimme 1.5.1)"
    fi
  ;;
  install)
    pip install tox
    if [ "x$BOULDER_INTEGRATION" != "x" ]; then
      integration_install
    fi
    ;;
  script)
    export TOXENV
    tox
    if [ "x$BOULDER_INTEGRATION" != "x" ]; then
      integration_script
    fi
    ;;
esac
