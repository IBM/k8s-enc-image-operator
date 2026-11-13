.PHONY: vendor check all build fmt copyright clean operator operator-push operator-bundle e2e-helm e2e-helm-containerd e2e-helm-crio FORCE

all: build

check:
	make vendor
	make fmt
	make build
	make test
	make clean

build: bin/keysync

fmt: 
	go fmt ./...
	scripts/copyright-check.sh
	gosec ./...
	golangci-lint run --timeout 10m0s

copyright:
	scripts/copyright.sh

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
		go mod verify

test:
	go test ./...

# End-to-end tests of the helm chart, see scripts/e2e-helm.sh
# (E2E_RUNTIME selects the runtime for e2e-helm, default: containerd)
e2e-helm:
	scripts/e2e-helm.sh

e2e-helm-containerd:
	E2E_RUNTIME=containerd scripts/e2e-helm.sh

e2e-helm-crio:
	E2E_RUNTIME=cri-o scripts/e2e-helm.sh

clean:
	rm -rf bin/
