#!/bin/sh

mkdir public_html
cd public_html
if python -V 2>&1 | grep -q "Python 3."; then
  python -m http.server ${PORT?} &
else
  python -m SimpleHTTPServer ${PORT?} &
fi
