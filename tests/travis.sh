#!/bin/sh -xe

integration_install() {
  ./venv.sh
}

integration_script() {
  . venv/bin/activate
  pip -V
}

case $1 in
  install)
    [ "$BOULDER_INTEGRATION" = "1" ] && integration_install || \
      travis_retry pip install
    ;;
  script)
    export TOXENV
    [ "$BOULDER_INTEGRATION" = "1" ] && integration_script || tox
    ;;
esac
