#!/bin/sh

# This script is sourced in .travis.yml, and `source` doesn't take
# into evaluate the shebang line, so it needs to be set explicitly
# here. Otherwise tests will happily pass despite non-zero exit codes
# from some of the commands in this file (#39).
set -xe

SERVER=http://localhost:4000/directory
TOS_SHA256=3ae9d8149e59b8845069552fdae761c3a042fc5ede1fcdf8f37f7aa4707c4d6e
PORT=5002

integration_install() {
  # `/...` avoids `no buildable Go source files` errors, for more info
  # see `go help packages`
  go get -d github.com/letsencrypt/boulder/... &
  (wget https://github.com/jsha/boulder-tools/raw/master/goose.gz && \
   mkdir $GOPATH/bin && \
   zcat goose.gz > $GOPATH/bin/goose && \
   chmod +x $GOPATH/bin/goose) &
  # listenbuddy is needed for ./start.py
  go get github.com/jsha/listenbuddy &

  wait

  cd $GOPATH/src/github.com/letsencrypt/boulder
  ./test/create_db.sh
  go run cmd/rabbitmq-setup/main.go -server amqp://localhost
  ./start.py &
  cd -

  mkdir public_html
  cd public_html
  if python -V 2>&1 | grep -q "Python 3."; then
    python -m http.server ${PORT?} &
  else
    python -m SimpleHTTPServer ${PORT?} &
  fi
  cd -

  while ! curl ${SERVER?} >/dev/null 2>&1; do
    printf .
    sleep 5
  done
  echo
}

integration_script() {
  . .tox/$TOXENV/bin/activate
  pip -V

  simp_le -v --server ${SERVER?} --tos_sha256 ${TOS_SHA256?} \
    -f account_key.json -f key.pem -f cert.pem -f fullchain.pem \
    -d le.wtf:public_html

  simp_le -v --server ${SERVER?} --revoke -f account_key.json -f cert.pem
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
