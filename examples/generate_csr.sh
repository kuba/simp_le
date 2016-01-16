#!/bin/sh
#
# This script generates a simple SAN CSR to be used with ACME CA.

if [ "$#" -lt 1 ]
then
  echo "Usage: $0 name [name...]" >&2
  exit 1
fi

OUTFORM=${OUTFORM:-pem}
OUT="csr.${OUTFORM}"
# 512 or 1024 too low for Boulder, 2048 is smallest for tests
BITS="${BITS:-4096}"
KEYOUT=key.pem

names="DNS:$1"
shift
for x in "$@"
do
  names="$names,DNS:$x"
done

openssl_cnf=$(mktemp)
cat >"${openssl_cnf}" <<EOF
[ req ]
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
[ san ]
subjectAltName=\${ENV::SAN}
EOF

SAN="$names" openssl req -config "${openssl_cnf}" \
  -new -nodes -subj '/' -reqexts san \
  -out "${OUT}" \
  -keyout "${KEYOUT}" \
  -newkey rsa:"${BITS}" \
  -outform "${OUTFORM}"

rm "${openssl_cnf}"
