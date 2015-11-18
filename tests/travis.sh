#!/bin/sh -xe

integration_install() {
  ./venv.sh &

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
  ./start.py &
  cd -

  mkdir public_html
  python -m SimpleHTTPServer 5002 &
}

integration_script() {
  . venv/bin/activate
  pip -V
  alias simp_le_test="simp_le -v --server http://localhost:4000/directory"

  simp_le_test -f key.pem -f cert.pem -f fullchain.pem -d le.wtf:public_html
}

case $1 in
  install)
    [ "$BOULDER_INTEGRATION" = "1" ] && integration_install || pip install tox
    ;;
  script)
    export TOXENV
    [ "$BOULDER_INTEGRATION" = "1" ] && integration_script || tox
    ;;
esac
