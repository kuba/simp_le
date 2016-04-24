#!/bin/sh

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
