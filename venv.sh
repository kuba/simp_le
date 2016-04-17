#!/bin/sh

virtualenv --no-site-packages venv
export PATH="$PWD/venv/bin:$PATH"  # #49, activate script requires bash
for pkg in setuptools pip wheel
do
  pip install -U "${pkg?}"
done
pip install -e .
