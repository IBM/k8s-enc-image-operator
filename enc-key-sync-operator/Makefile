.PHONY: build push

build: 
	operator-sdk build docker.io/lumjjb/enc-key-sync-operator:v0.0.1

push: build
	docker push docker.io/lumjjb/enc-key-sync-operator:v0.0.1
