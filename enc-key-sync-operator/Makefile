.PHONY: build push bundle

build: 
	operator-sdk build docker.io/lumjjb/enc-key-sync-operator:v0.0.1

push: build
	docker push docker.io/lumjjb/enc-key-sync-operator:v0.0.1

bundle:
	operator-sdk bundle create docker.io/lumjjb/enc-key-sync-operator-bundle:v0.0.1
	docker push docker.io/lumjjb/enc-key-sync-operator-bundle:v0.0.1
	operator-sdk bundle validate  docker.io/lumjjb/enc-key-sync-operator-bundle:v0.0.1
