#!/bin/sh
#
# Dummy example external script that loads/saves
# account_key/key/cert/chain to /tmp/foo. Experiment e.g. by running
# `./external.sh persisted`, `echo foo | ./external.sh save; cat
# /tmp/foo`, or `./external.sh load`; note the exit codes. The plugin
# can be loaded by running `simp_le -f external.sh`.

case $1 in
  save) cat - > /tmp/foo;;
  load) [ ! -f /tmp/foo ] || cat /tmp/foo;;
  persisted) echo account_key key cert chain;;
esac
