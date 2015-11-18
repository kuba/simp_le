#!/bin/sh -xe

SERVER=http://localhost:4000/directory
PORT=5002

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
  python -m SimpleHTTPServer ${PORT?} &

  while ! curl ${SERVER?} >/dev/null 2>&1; do
    printf .
    sleep 5
  done
  echo
}

integration_script() {
  . venv/bin/activate
  pip -V

  simp_le -v --server ${SERVER?} \
    -f key.pem -f cert.pem -f fullchain.pem -d le.wtf:public_html
}

case $1 in
  install)
    if [ "$BOULDER_INTEGRATION" = "1" ]; then
      integration_install
    else
      pip install tox
    fi
    ;;
  script)
    export TOXENV
    if [ "$BOULDER_INTEGRATION" = "1" ]; then
      integration_script
    else
      tox
    fi
    ;;
esac
