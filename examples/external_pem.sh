#!/bin/sh
# Dummy example external script that loads/saves key/cert/chain to
# /tmp/foo; `simp_le -f external_pem.sh`.

load () {
  cat /tmp/foo
}

save () {
  cat - > /tmp/foo
}

persisted () {
  echo key cert chain
}

case $1 in
  save)
    save
    ;;
  load)
    load
    ;;
  persisted)
    persisted
    ;;
esac
