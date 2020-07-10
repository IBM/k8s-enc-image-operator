.PHONY: vendor check all build fmt clean

all: build

check: fmt vendor build clean

build: bin/keysync

fmt: 
	go fmt $(go list ./...)

bin/keysync: keysync/* main_keysync.go
	go build -o bin/keysync main_keysync.go


vendor:
	GO111MODULE=on \
		go mod tidy && \
		go mod vendor && \
		go mod verify

clean:
	rm -rf bin/
