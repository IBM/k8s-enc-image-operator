.PHONY: vendor check all build fmt clean operator operator-push operator-bundle FORCE

all: build

check: fmt vendor build clean

build: bin/keysync

fmt: 
	go fmt ./...

bin/keysync: keysync/* main_keysync.go
	go build -o bin/keysync main_keysync.go

container: bin/keysync
	docker build -f Dockerfile.keysync -t keysync:latest .

container-push: container
	docker tag keysync:latest lumjjb/keysync:latest
	docker push lumjjb/keysync:latest

operator:
	make build -C enc-key-sync-operator

operator-push:
	make push -C enc-key-sync-operator

operator-bundle:
	make bundle -C enc-key-sync-operator

vendor:
	GO111MODULE=on \
		go mod tidy && \
		go mod vendor && \
		go mod verify

clean:
	rm -rf bin/
