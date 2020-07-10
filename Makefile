.PHONY: vendor

all: build

build: bin/keysync

fmt: 
	go fmt *.go

bin/keysync: keysync/* main_keysync.go
	go build -o bin/keysync main_keysync.go


vendor:
	GO111MODULE=on \
		go mod tidy && \
		go mod vendor && \
		go mod verify

clean:
	rm -rf bin/
