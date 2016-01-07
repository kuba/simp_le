#!/bin/sh
#
# Dummy example external script that loads/saves
# account_key/key/cert/chain to /tmp/foo; Usage: `simp_le -f
# external.sh`.

load () {
  cat /tmp/foo || true
}

save () {
  cat - > /tmp/foo
}

persisted () {
  echo account_key key cert chain
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
